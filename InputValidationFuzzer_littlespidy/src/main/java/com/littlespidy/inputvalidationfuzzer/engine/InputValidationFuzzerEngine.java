package com.littlespidy.inputvalidationfuzzer.engine;

import com.littlespidy.inputvalidationfuzzer.model.ConfiguredHeader;
import com.littlespidy.inputvalidationfuzzer.model.FuzzPayload;
import com.littlespidy.inputvalidationfuzzer.model.FuzzResult;
import com.littlespidy.inputvalidationfuzzer.model.FuzzerConfig;
import com.littlespidy.inputvalidationfuzzer.model.TrafficCandidate;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Core execution engine that supports single or multi-target batch fuzzing
 * across request parameters with custom headers & session auth injection.
 *
 * @author littlespidy
 */
public class InputValidationFuzzerEngine {
    private final MontoyaApi api;
    private final FuzzerConfig config;
    private final ExecutionPauseController pauseController = new ExecutionPauseController();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger resultIdCounter = new AtomicInteger(1);
    private ExecutorService executor;

    public InputValidationFuzzerEngine(MontoyaApi api, FuzzerConfig config) {
        this.api = api;
        this.config = config;
    }

    public ExecutionPauseController getPauseController() {
        return pauseController;
    }

    public boolean isRunning() {
        return running.get();
    }

    public void stop() {
        running.set(false);
        pauseController.resume();
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }

    public void runFuzzBatch(
        List<TrafficCandidate> targets,
        List<ConfiguredHeader> sessionHeaders,
        Consumer<FuzzResult> resultConsumer,
        Consumer<String> statusConsumer,
        Runnable onComplete
    ) {
        if (running.get() || targets == null || targets.isEmpty()) {
            return;
        }

        running.set(true);
        resultIdCounter.set(1);
        executor = Executors.newFixedThreadPool(Math.max(1, config.getMaxConcurrentThreads()));

        Thread worker = new Thread(() -> {
            try {
                int totalTargets = targets.size();
                int targetIdx = 0;

                for (TrafficCandidate target : targets) {
                    if (!running.get()) break;

                    targetIdx++;
                    final int currentTargetNum = targetIdx;
                    HttpRequest baseRequest = target.request();
                    HttpResponse baseResponse = target.response();

                    if (baseRequest == null) continue;

                    // Apply custom session cookies or auth headers if present
                    if (sessionHeaders != null && !sessionHeaders.isEmpty()) {
                        baseRequest = applySessionHeaders(baseRequest, sessionHeaders);
                    }

                    // Re-fetch baseline response if missing or custom headers were added
                    if (baseResponse == null || (sessionHeaders != null && !sessionHeaders.isEmpty())) {
                        statusConsumer.accept("Target " + currentTargetNum + "/" + totalTargets + ": Sending baseline control request...");
                        HttpRequestResponse baseRr = api.http().sendRequest(baseRequest);
                        if (baseRr.hasResponse()) {
                            baseResponse = baseRr.response();
                        } else {
                            continue;
                        }
                    }

                    int baseStatus = baseResponse.statusCode();
                    int baseBodyLen = baseResponse.body().length();

                    var parameters = baseRequest.parameters();
                    List<ParsedHttpParameter> targetParameters = parameters.stream()
                        .filter(p -> isParamAllowed(p.type()))
                        .collect(Collectors.toList());

                    if (targetParameters.isEmpty()) {
                        continue;
                    }

                    List<FuzzPayload> payloads = config.getPayloads();
                    int totalProbesForTarget = targetParameters.size() * payloads.size();
                    AtomicInteger completedProbes = new AtomicInteger(0);

                    statusConsumer.accept("Target " + currentTargetNum + "/" + totalTargets + " (" + baseRequest.method() + " " + baseRequest.path() + "): Fuzzing " + targetParameters.size() + " param(s)...");

                    List<Future<?>> futures = new ArrayList<>();

                    for (ParsedHttpParameter targetParam : targetParameters) {
                        for (FuzzPayload payload : payloads) {
                            if (!running.get()) break;

                            final HttpRequest finalBaseReq = baseRequest;
                            final HttpResponse finalBaseResp = baseResponse;
                            Future<?> future = executor.submit(() -> {
                                if (!running.get()) return;

                                pauseController.awaitIfPaused(running::get);
                                if (!running.get()) return;

                                try {
                                    if (config.getDelayBetweenRequestsMs() > 0) {
                                        Thread.sleep(config.getDelayBetweenRequestsMs());
                                    }

                                    HttpRequest mutatedRequest = finalBaseReq.withUpdatedParameters(
                                        HttpParameter.parameter(
                                            targetParam.name(),
                                            payload.value(),
                                            targetParam.type()
                                        )
                                    );

                                    // Ensure custom session headers are preserved on mutated request
                                    if (sessionHeaders != null && !sessionHeaders.isEmpty()) {
                                        mutatedRequest = applySessionHeaders(mutatedRequest, sessionHeaders);
                                    }

                                    HttpRequestResponse rr = api.http().sendRequest(mutatedRequest);
                                    if (!rr.hasResponse()) {
                                        return;
                                    }

                                    HttpResponse resp = rr.response();
                                    int respStatus = resp.statusCode();
                                    int respBodyLen = resp.body().length();
                                    String respBody = resp.bodyToString().toLowerCase();
                                    String respContentType = resp.headerValue("Content-Type");
                                    if (respContentType == null) respContentType = "";

                                    boolean serverError = (respStatus >= 500);
                                    boolean statusChanged = (respStatus != baseStatus && respStatus >= 400);

                                    boolean errorFound = false;
                                    String matchedError = "";
                                    for (String sig : config.getErrorSignatures()) {
                                        if (respBody.contains(sig.toLowerCase())) {
                                            errorFound = true;
                                            matchedError = sig;
                                            break;
                                        }
                                    }

                                    boolean payloadReflected = !payload.value().isEmpty()
                                        && respBody.contains(payload.value().toLowerCase());

                                    boolean sizeDiff = baseBodyLen > 0
                                        && ((double) respBodyLen / baseBodyLen) * 100 > config.getSizeDiffPercent();

                                    String signal = "";
                                    String severity = "Info";
                                    String evidence = "";

                                    if (serverError || errorFound) {
                                        severity = serverError ? "High" : "Medium";
                                        signal = serverError ? "5xx Server Error (" + respStatus + ")" : "Error Signature (" + matchedError + ")";
                                        evidence = serverError
                                            ? "Server returned HTTP " + respStatus + " (baseline was " + baseStatus + ")"
                                            : "Error signature matched: " + matchedError;
                                    } else if (payloadReflected) {
                                        severity = "Medium";
                                        signal = "Payload Reflected";
                                        evidence = "Payload \"" + payload.value() + "\" was reflected unencoded in response body.";
                                    } else if (statusChanged || sizeDiff) {
                                        severity = "Low";
                                        if (statusChanged && sizeDiff) {
                                            signal = "Status Changed (" + baseStatus + "->" + respStatus + ") & Size Anomaly (+" + (respBodyLen - baseBodyLen) + "B)";
                                        } else if (statusChanged) {
                                            signal = "Status Changed (" + baseStatus + "->" + respStatus + ")";
                                        } else {
                                            signal = "Size Anomaly (" + baseBodyLen + "B -> " + respBodyLen + "B)";
                                        }
                                        evidence = "Baseline status: " + baseStatus + ", baseline length: " + baseBodyLen + "B";
                                    } else {
                                        signal = "Normal (" + respStatus + ")";
                                    }

                                    FuzzResult result = new FuzzResult(
                                        resultIdCounter.getAndIncrement(),
                                        targetParam.name(),
                                        targetParam.type().name(),
                                        payload.name(),
                                        payload.value(),
                                        baseStatus,
                                        baseBodyLen,
                                        respStatus,
                                        respBodyLen,
                                        respContentType,
                                        signal,
                                        severity,
                                        evidence,
                                        mutatedRequest,
                                        resp,
                                        finalBaseReq,
                                        finalBaseResp,
                                        rr,
                                        ZonedDateTime.now()
                                    );

                                    resultConsumer.accept(result);

                                    int done = completedProbes.incrementAndGet();
                                    statusConsumer.accept("Target " + currentTargetNum + "/" + totalTargets + ": " + done + " / " + totalProbesForTarget + " probes completed.");

                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                } catch (Exception e) {
                                    api.logging().logToError("Error during fuzz request: " + e.getMessage());
                                }
                            });

                            futures.add(future);
                        }
                    }

                    for (Future<?> f : futures) {
                        try {
                            f.get();
                        } catch (Exception ignored) {}
                    }
                }

                statusConsumer.accept("Fuzzing finished across " + targets.size() + " target endpoint(s).");

            } catch (Exception e) {
                api.logging().logToError("Error running fuzzer engine: " + e.getMessage());
                statusConsumer.accept("Fuzzing stopped with error: " + e.getMessage());
            } finally {
                running.set(false);
                if (onComplete != null) {
                    onComplete.run();
                }
            }
        }, "InputValidationFuzzer-BatchWorker");

        worker.setDaemon(true);
        worker.start();
    }

    public HttpRequest applySessionHeaders(HttpRequest request, List<ConfiguredHeader> sessionHeaders) {
        if (request == null || sessionHeaders == null || sessionHeaders.isEmpty()) {
            return request;
        }

        HttpRequest mutated = request;
        for (ConfiguredHeader ch : sessionHeaders) {
            if (mutated.hasHeader(ch.name())) {
                mutated = mutated.withUpdatedHeader(ch.name(), ch.value());
            } else {
                mutated = mutated.withAddedHeader(ch.name(), ch.value());
            }
        }
        return mutated;
    }

    private boolean isParamAllowed(HttpParameterType type) {
        return switch (type) {
            case URL -> config.isFuzzUrlParams();
            case BODY -> config.isFuzzBodyParams();
            case COOKIE -> config.isFuzzCookieParams();
            case JSON -> config.isFuzzJsonParams();
            case XML, XML_ATTRIBUTE -> config.isFuzzXmlParams();
            case MULTIPART_ATTRIBUTE -> config.isFuzzMultipartParams();
        };
    }
}
