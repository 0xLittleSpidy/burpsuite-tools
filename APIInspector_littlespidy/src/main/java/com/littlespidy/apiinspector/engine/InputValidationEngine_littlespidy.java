// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.model.InputValidationTechnique_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy.ValidationSeverity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Execution engine for Input Validation testing and fuzzing using the Montoya API.
 */
public class InputValidationEngine_littlespidy {

    private final MontoyaApi api;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private ExecutorService threadPool;

    public InputValidationEngine_littlespidy(MontoyaApi api) {
        this.api = api;
    }

    public void cancel() {
        cancelled.set(true);
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdownNow();
        }
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    public void executeTestsAsync(
            HttpRequest baseRequest,
            List<InputValidationTechnique_littlespidy> techniques,
            int threadCount,
            int delayMs,
            InputValidationProgressListener_littlespidy listener) {

        cancelled.set(false);
        int threads = Math.max(1, threadCount);
        this.threadPool = Executors.newFixedThreadPool(threads);

        Thread runner = new Thread(() -> {
            try {
                if (baseRequest == null) {
                    if (listener != null) {
                        listener.onStatusUpdate("Error: No target request provided", 0, 0);
                        listener.onAllTestsCompleted();
                    }
                    return;
                }

                List<ParsedHttpParameter> params = new ArrayList<>();
                try {
                    params.addAll(baseRequest.parameters());
                } catch (Exception ignored) {
                }

                // If no parameters found, add a placeholder query parameter to test endpoint
                boolean syntheticParam = false;
                if (params.isEmpty()) {
                    syntheticParam = true;
                }

                List<InputValidationTechnique_littlespidy> activeTechs = new ArrayList<>();
                for (InputValidationTechnique_littlespidy t : techniques) {
                    if (t.isEnabled()) {
                        activeTechs.add(t);
                    }
                }

                int totalTasks = 0;
                int paramCount = syntheticParam ? 1 : params.size();
                for (InputValidationTechnique_littlespidy tech : activeTechs) {
                    totalTasks += (paramCount * tech.getSamplePayloads().size());
                }

                final int finalTotal = totalTasks;
                AtomicInteger completedCount = new AtomicInteger(0);
                AtomicInteger idCounter = new AtomicInteger(1);

                String method = baseRequest.method();
                String targetUrl = baseRequest.url();

                for (InputValidationTechnique_littlespidy tech : activeTechs) {
                    for (String payload : tech.getSamplePayloads()) {
                        if (syntheticParam) {
                            scheduleTask(baseRequest, "input", payload, tech, method, targetUrl,
                                    threadPool, delayMs, idCounter, completedCount, finalTotal, listener, true);
                        } else {
                            for (ParsedHttpParameter p : params) {
                                scheduleTask(baseRequest, p.name(), payload, tech, method, targetUrl,
                                        threadPool, delayMs, idCounter, completedCount, finalTotal, listener, false);
                            }
                        }
                    }
                }

                threadPool.shutdown();
                try {
                    threadPool.awaitTermination(30, TimeUnit.MINUTES);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }

                if (listener != null) {
                    listener.onAllTestsCompleted();
                }
            } catch (Exception e) {
                if (listener != null) {
                    listener.onStatusUpdate("Fuzzing run completed with message: " + e.getMessage(), 0, 0);
                    listener.onAllTestsCompleted();
                }
            }
        }, "InputValidation-Engine-Runner_littlespidy");

        runner.setDaemon(true);
        runner.start();
    }

    private void scheduleTask(
            HttpRequest baseRequest, String paramName, String payload,
            InputValidationTechnique_littlespidy tech, String method, String targetUrl,
            ExecutorService pool, int delayMs, AtomicInteger idCounter,
            AtomicInteger completedCount, int total,
            InputValidationProgressListener_littlespidy listener,
            boolean isSynthetic) {

        if (cancelled.get()) return;

        pool.submit(() -> {
            if (cancelled.get()) return;

            try {
                if (delayMs > 0) {
                    Thread.sleep(delayMs);
                }

                HttpRequest mutatedRequest;
                if (isSynthetic) {
                    mutatedRequest = baseRequest.withAddedParameters(HttpParameter.urlParameter(paramName, payload));
                } else {
                    mutatedRequest = baseRequest.withUpdatedParameters(HttpParameter.urlParameter(paramName, payload));
                }

                HttpRequestResponse responsePair = null;
                if (api != null && api.http() != null) {
                    responsePair = api.http().sendRequest(mutatedRequest);
                }

                int currentId = idCounter.getAndIncrement();
                InputValidationTestResult_littlespidy res = evaluateFuzzResponse(
                        currentId, method, targetUrl, paramName, tech.getCategory(),
                        payload, tech.getErrorSignatures(), responsePair
                );

                int done = completedCount.incrementAndGet();
                if (listener != null) {
                    listener.onFuzzTestCompleted(res);
                    listener.onStatusUpdate("Fuzzed " + done + "/" + total + " inputs", done, total);
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (Exception ex) {
                int done = completedCount.incrementAndGet();
                if (listener != null) {
                    listener.onStatusUpdate("Fuzzing error: " + ex.getMessage(), done, total);
                }
            }
        });
    }

    public static InputValidationTestResult_littlespidy evaluateFuzzResponse(
            int id, String method, String targetUrl, String paramName,
            String category, String payload, List<String> errorSignatures,
            HttpRequestResponse message) {

        if (message == null || !message.hasResponse()) {
            return new InputValidationTestResult_littlespidy(
                    id, method, targetUrl, paramName, category, payload,
                    0, 0, "No response received", ValidationSeverity.INFO, message
            );
        }

        HttpResponse response = message.response();
        int statusCode = response.statusCode();
        int length = response.body().length();
        String body = response.bodyToString();
        String lowerBody = body != null ? body.toLowerCase(Locale.ROOT) : "";

        String detectionIndicator = "Normal response";
        ValidationSeverity severity = ValidationSeverity.INFO;

        // Check for specific error signatures
        boolean signatureMatched = false;
        if (errorSignatures != null) {
            for (String sig : errorSignatures) {
                if (!sig.isBlank() && lowerBody.contains(sig.toLowerCase(Locale.ROOT))) {
                    detectionIndicator = "Matched signature: " + sig;
                    severity = ValidationSeverity.HIGH;
                    signatureMatched = true;
                    break;
                }
            }
        }

        if (!signatureMatched) {
            // Check for payload reflection in body
            if (payload.length() > 3 && body != null && body.contains(payload)) {
                detectionIndicator = "Payload reflected unencoded";
                severity = category.toLowerCase(Locale.ROOT).contains("xss") ? ValidationSeverity.HIGH : ValidationSeverity.MEDIUM;
            } else if (statusCode >= 500) {
                detectionIndicator = "Server error " + statusCode + " triggered";
                severity = ValidationSeverity.MEDIUM;
            } else if (statusCode == 400 || statusCode == 422) {
                detectionIndicator = "Rejected with status " + statusCode;
                severity = ValidationSeverity.LOW;
            }
        }

        return new InputValidationTestResult_littlespidy(
                id, method, targetUrl, paramName, category, payload,
                statusCode, length, detectionIndicator, severity, message
        );
    }
}
