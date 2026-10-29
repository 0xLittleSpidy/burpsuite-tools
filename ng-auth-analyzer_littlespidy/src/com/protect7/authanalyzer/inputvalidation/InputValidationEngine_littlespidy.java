// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.inputvalidation;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;

/**
 * High-performance concurrency engine for automated parameter fuzzing.
 */
public class InputValidationEngine_littlespidy {

    private static ExecutorService executor;

    public static synchronized ExecutorService getExecutor(int threads) {
        if (executor == null || executor.isShutdown()) {
            executor = Executors.newFixedThreadPool(Math.max(1, threads));
        }
        return executor;
    }

    public static void executeTestsAsync(
            IHttpRequestResponse messageInfo,
            InputValidationConfig_littlespidy config,
            Consumer<InputValidationTestResult_littlespidy> resultConsumer,
            AtomicInteger idCounter
    ) {
        if (messageInfo == null || messageInfo.getRequest() == null || BurpExtender.api == null) {
            return;
        }

        ExecutorService pool = getExecutor(config.getMaxConcurrentThreads());
        pool.submit(() -> {
            try {
                IHttpService svc = messageInfo.getHttpService();
                if (svc == null) return;

                boolean secure = "https".equalsIgnoreCase(svc.getProtocol());
                HttpService montoyaSvc = HttpService.httpService(svc.getHost(), svc.getPort(), secure);
                HttpRequest baseReq = HttpRequest.httpRequest(montoyaSvc, ByteArray.byteArray(messageInfo.getRequest()));

                HttpResponse baseResp;
                if (messageInfo.getResponse() != null && messageInfo.getResponse().length > 0) {
                    baseResp = HttpResponse.httpResponse(ByteArray.byteArray(messageInfo.getResponse()));
                } else {
                    HttpRequestResponse baseRr = BurpExtender.api.http().sendRequest(baseReq);
                    if (baseRr.hasResponse()) {
                        baseResp = baseRr.response();
                    } else {
                        return;
                    }
                }

                int baseStatus = baseResp.statusCode();
                int baseLen = baseResp.body().length();

                List<ParsedHttpParameter> params = baseReq.parameters().stream()
                        .filter(p -> isParamAllowed(p.type(), config))
                        .collect(Collectors.toList());

                if (params.isEmpty()) {
                    return;
                }

                List<InputValidationPayload_littlespidy> activePayloads = new ArrayList<>();
                for (InputValidationPayload_littlespidy p : config.getPayloads()) {
                    if (p.isEnabled()) {
                        activePayloads.add(p);
                    }
                }

                if (activePayloads.isEmpty()) {
                    return;
                }

                String method = baseReq.method();
                String host = svc.getHost();
                String path = baseReq.path();
                CustomHttpService_littlespidy customSvc = new CustomHttpService_littlespidy(host, svc.getPort(), svc.getProtocol());

                for (ParsedHttpParameter param : params) {
                    for (InputValidationPayload_littlespidy payload : activePayloads) {
                        try {
                            if (config.getDelayBetweenRequestsMs() > 0) {
                                Thread.sleep(config.getDelayBetweenRequestsMs());
                            }

                            HttpRequest mutatedReq = baseReq.withUpdatedParameters(
                                    HttpParameter.parameter(param.name(), payload.getValue(), param.type())
                            );

                            HttpRequestResponse mutatedRr = BurpExtender.api.http().sendRequest(mutatedReq);
                            if (!mutatedRr.hasResponse()) {
                                continue;
                            }

                            HttpResponse resp = mutatedRr.response();
                            int respStatus = resp.statusCode();
                            int respLen = resp.body().length();
                            String respBody = resp.bodyToString().toLowerCase(Locale.ROOT);

                            int sizeDiff = 0;
                            if (baseLen > 0) {
                                sizeDiff = (int) (((long) (respLen - baseLen) * 100) / baseLen);
                            }

                            // Anomaly evaluation
                            String anomaly = "Clean";
                            String evidence = "";

                            String matchedSig = null;
                            for (String sig : config.getErrorSignatures()) {
                                if (respBody.contains(sig.toLowerCase(Locale.ROOT))) {
                                    matchedSig = sig;
                                    break;
                                }
                            }

                            boolean payloadReflected = !payload.getValue().isEmpty()
                                    && payload.getValue().length() >= 3
                                    && respBody.contains(payload.getValue().toLowerCase(Locale.ROOT));

                            if (matchedSig != null) {
                                anomaly = "Error Signature (" + matchedSig + ")";
                                evidence = "Matched signature pattern: \"" + matchedSig + "\" in response body.";
                            } else if (payloadReflected) {
                                anomaly = "Reflected Input";
                                evidence = "Payload \"" + payload.getValue() + "\" was reflected unencoded in response.";
                            } else if (respStatus >= 500) {
                                anomaly = "HTTP 5xx Server Error (" + respStatus + ")";
                                evidence = "Server returned internal server error code " + respStatus + ".";
                            } else if (respStatus != baseStatus && respStatus >= 400) {
                                anomaly = "Status Shift (" + baseStatus + " -> " + respStatus + ")";
                                evidence = "Status code changed from baseline " + baseStatus + " to " + respStatus + ".";
                            } else if (Math.abs(sizeDiff) >= config.getSizeDiffPercent()) {
                                anomaly = "Size Delta (" + (sizeDiff >= 0 ? "+" : "") + sizeDiff + "%)";
                                evidence = "Response length shifted by " + sizeDiff + "% (Baseline: " + baseLen + " B, Fuzzed: " + respLen + " B).";
                            }

                            int nextId = idCounter != null ? idCounter.incrementAndGet() : 1;

                            CustomHttpRequestResponse_littlespidy fuzzedMessage = new CustomHttpRequestResponse_littlespidy(
                                    mutatedRr.request().toByteArray().getBytes(),
                                    mutatedRr.response().toByteArray().getBytes(),
                                    customSvc
                            );

                            InputValidationTestResult_littlespidy testResult = new InputValidationTestResult_littlespidy(
                                    nextId,
                                    payload.getCategory(),
                                    method,
                                    host,
                                    path,
                                    param.name(),
                                    param.type().name(),
                                    payload.getName(),
                                    payload.getValue(),
                                    baseStatus,
                                    respStatus,
                                    baseLen,
                                    respLen,
                                    sizeDiff,
                                    anomaly,
                                    evidence,
                                    fuzzedMessage,
                                    messageInfo
                            );

                            if (resultConsumer != null) {
                                resultConsumer.accept(testResult);
                            }

                        } catch (Exception ex) {
                            // Suppress individual request errors to avoid halting testing
                        }
                    }
                }
            } catch (Exception e) {
                // Background execution exception safeguard
            }
        });
    }

    private static boolean isParamAllowed(HttpParameterType type, InputValidationConfig_littlespidy config) {
        if (type == null || config == null) return false;
        switch (type) {
            case URL:
                return config.isFuzzUrlParams();
            case BODY:
                return config.isFuzzBodyParams();
            case JSON:
                return config.isFuzzJsonParams();
            case XML:
            case XML_ATTRIBUTE:
                return config.isFuzzXmlParams();
            case MULTIPART_ATTRIBUTE:
                return config.isFuzzMultipartParams();
            case COOKIE:
                return config.isFuzzCookieParams();
            default:
                return false;
        }
    }
}
