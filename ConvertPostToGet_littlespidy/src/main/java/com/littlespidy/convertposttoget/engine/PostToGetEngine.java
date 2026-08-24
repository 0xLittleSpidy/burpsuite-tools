package com.littlespidy.convertposttoget.engine;

import com.littlespidy.convertposttoget.model.ConfiguredHeader;
import com.littlespidy.convertposttoget.model.ConversionResult;
import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import com.littlespidy.convertposttoget.model.PostCandidate;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Core execution engine that converts POST targets to GET, dispatches requests,
 * evaluates response signals, and streams results in real time.
 *
 * @author littlespidy
 */
public class PostToGetEngine {
    private final MontoyaApi api;
    private final ConvertPostToGetConfig config;
    private final PostToGetConverter converter;
    private final ExecutionPauseController pauseController = new ExecutionPauseController();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger resultIdCounter = new AtomicInteger(1);
    private ExecutorService executor;

    public PostToGetEngine(MontoyaApi api, ConvertPostToGetConfig config) {
        this.api = api;
        this.config = config;
        this.converter = new PostToGetConverter(api, config);
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

    public void runConversionBatch(
        List<PostCandidate> targets,
        List<ConfiguredHeader> sessionHeaders,
        Consumer<ConversionResult> resultConsumer,
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
                AtomicInteger completedCount = new AtomicInteger(0);

                statusConsumer.accept("Starting POST to GET conversion across " + totalTargets + " target(s)...");

                List<Future<?>> futures = new ArrayList<>();

                for (PostCandidate target : targets) {
                    if (!running.get()) break;

                    Future<?> future = executor.submit(() -> {
                        if (!running.get()) return;

                        pauseController.awaitIfPaused(running::get);
                        if (!running.get()) return;

                        try {
                            if (config.getDelayBetweenRequestsMs() > 0) {
                                Thread.sleep(config.getDelayBetweenRequestsMs());
                            }

                            HttpRequest originalPostReq = target.request();
                            HttpResponse originalPostResp = target.response();

                            // Inject session headers to baseline POST if provided
                            if (sessionHeaders != null && !sessionHeaders.isEmpty()) {
                                originalPostReq = converter.applySessionHeaders(originalPostReq, sessionHeaders);
                            }

                            // Re-fetch baseline response if missing or if custom headers applied
                            if (originalPostResp == null || (sessionHeaders != null && !sessionHeaders.isEmpty())) {
                                HttpRequestResponse postRr = api.http().sendRequest(originalPostReq);
                                if (postRr.hasResponse()) {
                                    originalPostResp = postRr.response();
                                }
                            }

                            int baseStatus = originalPostResp != null ? originalPostResp.statusCode() : 0;
                            int baseBodyLen = originalPostResp != null ? originalPostResp.body().length() : 0;

                            // Convert POST -> GET
                            HttpRequest getRequest = converter.convertPostToGet(target.request(), sessionHeaders);

                            HttpRequestResponse getRr = api.http().sendRequest(getRequest);
                            if (!getRr.hasResponse()) {
                                return;
                            }

                            HttpResponse getResp = getRr.response();
                            int getStatus = getResp.statusCode();
                            int getBodyLen = getResp.body().length();
                            String getContentType = getResp.headerValue("Content-Type");
                            if (getContentType == null) getContentType = "";

                            // Evaluate Signals & Severity
                            String signal = "";
                            String severity = "Info";
                            String evidence = "";

                            boolean isBypass = (baseStatus == 401 || baseStatus == 403) && (getStatus == 200 || getStatus == 302);
                            boolean isMethodPermitted = (getStatus >= 200 && getStatus < 300);
                            boolean isMethodNotAllowed = (getStatus == 405 || getStatus == 501);
                            boolean isServerError = (getStatus >= 500);

                            if (isBypass) {
                                severity = "High";
                                signal = "BYPASS DETECTED (" + baseStatus + " -> " + getStatus + ")";
                                evidence = "Original POST returned HTTP " + baseStatus + " (Blocked). Converted GET returned HTTP " + getStatus + " (Accepted). Possible Authorization / WAF bypass!";
                            } else if (isServerError) {
                                severity = "High";
                                signal = "5xx Server Error (" + getStatus + ")";
                                evidence = "Converted GET caused backend error/crash (HTTP " + getStatus + ").";
                            } else if (isMethodPermitted) {
                                severity = "Medium";
                                signal = "200 OK (Method Permitted / CSRF Potential)";
                                evidence = "Backend accepted the GET method with query parameters. If state-changing, this may allow CSRF without POST token validation.";
                            } else if (isMethodNotAllowed) {
                                severity = "Info";
                                signal = "Method Not Allowed (" + getStatus + ")";
                                evidence = "Server explicitly rejected GET method (HTTP " + getStatus + ").";
                            } else {
                                severity = "Low";
                                signal = "Status (" + baseStatus + " -> " + getStatus + ")";
                                evidence = "Baseline POST: " + baseStatus + " (" + baseBodyLen + "B), Converted GET: " + getStatus + " (" + getBodyLen + "B)";
                            }

                            ConversionResult res = new ConversionResult(
                                resultIdCounter.getAndIncrement(),
                                "GET",
                                getRequest.url(),
                                getRequest.httpService() != null ? getRequest.httpService().host() : "",
                                getRequest.path(),
                                baseStatus,
                                baseBodyLen,
                                getStatus,
                                getBodyLen,
                                getContentType,
                                signal,
                                severity,
                                evidence,
                                originalPostReq,
                                originalPostResp,
                                getRequest,
                                getResp,
                                getRr,
                                ZonedDateTime.now()
                            );

                            resultConsumer.accept(res);

                            int done = completedCount.incrementAndGet();
                            statusConsumer.accept("Progress: " + done + " / " + totalTargets + " conversions completed.");

                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } catch (Exception e) {
                            api.logging().logToError("Error during conversion test: " + e.getMessage());
                        }
                    });

                    futures.add(future);
                }

                for (Future<?> f : futures) {
                    try {
                        f.get();
                    } catch (Exception ignored) {}
                }

                statusConsumer.accept("Conversion test finished across " + completedCount.get() + " / " + totalTargets + " endpoints.");

            } catch (Exception e) {
                api.logging().logToError("Error running PostToGetEngine: " + e.getMessage());
                statusConsumer.accept("Engine stopped with error: " + e.getMessage());
            } finally {
                running.set(false);
                if (onComplete != null) {
                    onComplete.run();
                }
            }
        }, "PostToGetEngine-Worker");

        worker.setDaemon(true);
        worker.start();
    }
}
