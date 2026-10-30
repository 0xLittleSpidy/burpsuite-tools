// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationPayloadItem_littlespidy;
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
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private ExecutorService threadPool;

    public InputValidationEngine_littlespidy(MontoyaApi api) {
        this.api = api;
    }

    public void cancel() {
        cancelled.set(true);
        paused.set(false);
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdownNow();
        }
    }

    public void pause() {
        paused.set(true);
    }

    public void resume() {
        paused.set(false);
    }

    public boolean isPaused() {
        return paused.get();
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
        paused.set(false);
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

    /**
     * Executes individual payloads fuzzing across a single target request.
     */
    public void executeIndividualPayloadsAsync(
            HttpRequest baseRequest,
            List<InputValidationPayloadItem_littlespidy> payloadItems,
            int threadCount,
            int delayMs,
            InputValidationProgressListener_littlespidy listener) {

        cancelled.set(false);
        paused.set(false);
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

                boolean syntheticParam = params.isEmpty();
                List<InputValidationPayloadItem_littlespidy> activePayloads = new ArrayList<>();
                for (InputValidationPayloadItem_littlespidy p : payloadItems) {
                    if (p.isEnabled()) {
                        activePayloads.add(p);
                    }
                }

                int paramCount = syntheticParam ? 1 : params.size();
                int total = activePayloads.size() * paramCount;
                AtomicInteger completedCount = new AtomicInteger(0);
                AtomicInteger idCounter = new AtomicInteger(1);

                String method = baseRequest.method();
                String targetUrl = baseRequest.url();

                for (InputValidationPayloadItem_littlespidy payloadItem : activePayloads) {
                    if (cancelled.get()) break;

                    if (syntheticParam) {
                        schedulePayloadTask(baseRequest, "input", payloadItem, method, targetUrl,
                                threadPool, delayMs, idCounter, completedCount, total, listener, true);
                    } else {
                        for (ParsedHttpParameter p : params) {
                            schedulePayloadTask(baseRequest, p.name(), payloadItem, method, targetUrl,
                                    threadPool, delayMs, idCounter, completedCount, total, listener, false);
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
        }, "InputValidation-Individual-Runner_littlespidy");

        runner.setDaemon(true);
        runner.start();
    }

    /**
     * Executes individual payloads fuzzing across multiple collection endpoints.
     */
    public void executeEndpointsFuzzAsync(
            List<? extends EndpointSelectionItem_littlespidy> endpointItems,
            String defaultTargetBaseUrl,
            List<InputValidationPayloadItem_littlespidy> payloadItems,
            int threadCount,
            int delayMs,
            InputValidationProgressListener_littlespidy listener) {
        executeEndpointsFuzzAsync(endpointItems, defaultTargetBaseUrl, null, null, payloadItems, threadCount, delayMs, listener);
    }

    /**
     * Executes individual payloads fuzzing across multiple collection endpoints with an Auth Profile or custom session header.
     */
    public void executeEndpointsFuzzAsync(
            List<? extends EndpointSelectionItem_littlespidy> endpointItems,
            String defaultTargetBaseUrl,
            AuthProfile_littlespidy profile,
            String customAuthHeader,
            List<InputValidationPayloadItem_littlespidy> payloadItems,
            int threadCount,
            int delayMs,
            InputValidationProgressListener_littlespidy listener) {

        cancelled.set(false);
        paused.set(false);
        int threads = Math.max(1, threadCount);
        this.threadPool = Executors.newFixedThreadPool(threads);

        Thread runner = new Thread(() -> {
            try {
                List<InputValidationPayloadItem_littlespidy> activePayloads = new ArrayList<>();
                if (payloadItems != null) {
                    for (InputValidationPayloadItem_littlespidy p : payloadItems) {
                        if (p.isEnabled()) {
                            activePayloads.add(p);
                        }
                    }
                }

                List<EndpointSelectionItem_littlespidy> activeEndpoints = new ArrayList<>();
                if (endpointItems != null) {
                    for (EndpointSelectionItem_littlespidy item : endpointItems) {
                        if (item.selected) {
                            activeEndpoints.add(item);
                        }
                    }
                }

                if (activeEndpoints.isEmpty() || activePayloads.isEmpty()) {
                    if (listener != null) {
                        listener.onStatusUpdate("Completed (0 endpoints or payloads selected)", 0, 0);
                        listener.onAllTestsCompleted();
                    }
                    return;
                }

                int total = 0;
                List<EndpointTargetWork> workItems = new ArrayList<>();
                for (EndpointSelectionItem_littlespidy epItem : activeEndpoints) {
                    String baseUrl = (epItem.collection != null && epItem.collection.getTargetBaseUrl() != null && !epItem.collection.getTargetBaseUrl().isBlank())
                            ? epItem.collection.getTargetBaseUrl()
                            : (defaultTargetBaseUrl != null && !defaultTargetBaseUrl.isBlank() ? defaultTargetBaseUrl : "https://localhost");

                    HttpRequest baseReq;
                    try {
                        baseReq = AuthTestEngine_littlespidy.buildRequest(baseUrl, epItem.endpoint, profile, profile != null);
                    } catch (Exception ex) {
                        baseReq = HttpRequest.httpRequestFromUrl(baseUrl + epItem.endpoint.getPath());
                    }

                    if (customAuthHeader != null && !customAuthHeader.isBlank() && customAuthHeader.contains(":")) {
                        String[] parts = customAuthHeader.split(":", 2);
                        baseReq = baseReq.withAddedHeader(parts[0].trim(), parts[1].trim());
                    }

                    if (baseReq == null) continue;

                    List<String> paramNames = new ArrayList<>();
                    try {
                        for (ParsedHttpParameter p : baseReq.parameters()) {
                            paramNames.add(p.name());
                        }
                    } catch (Exception ignored) {
                    }

                    if (paramNames.isEmpty()) {
                        paramNames.add("input");
                    }

                    total += (paramNames.size() * activePayloads.size());
                    workItems.add(new EndpointTargetWork(baseReq, paramNames));
                }

                final int finalTotal = total;
                AtomicInteger completedCount = new AtomicInteger(0);
                AtomicInteger idCounter = new AtomicInteger(1);

                for (EndpointTargetWork work : workItems) {
                    if (cancelled.get()) break;

                    String method = work.baseRequest.method();
                    String targetUrl = work.baseRequest.url();

                    for (InputValidationPayloadItem_littlespidy payloadItem : activePayloads) {
                        if (cancelled.get()) break;

                        for (String paramName : work.paramNames) {
                            schedulePayloadTask(work.baseRequest, paramName, payloadItem, method, targetUrl,
                                    threadPool, delayMs, idCounter, completedCount, finalTotal, listener, false);
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
        }, "InputValidation-Endpoints-Runner_littlespidy");

        runner.setDaemon(true);
        runner.start();
    }

    private void schedulePayloadTask(
            HttpRequest baseRequest, String paramName, InputValidationPayloadItem_littlespidy payloadItem,
            String method, String targetUrl,
            ExecutorService pool, int delayMs, AtomicInteger idCounter,
            AtomicInteger completedCount, int total,
            InputValidationProgressListener_littlespidy listener,
            boolean isSynthetic) {

        if (cancelled.get()) return;

        pool.submit(() -> {
            if (cancelled.get()) return;

            while (paused.get() && !cancelled.get()) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }

            if (cancelled.get()) return;

            try {
                if (delayMs > 0) {
                    Thread.sleep(delayMs);
                }

                String payload = payloadItem.getPayload();
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
                        currentId, method, targetUrl, paramName, payloadItem.getCategory(),
                        payload, payloadItem.getDetectionSignatures(), responsePair
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

    private static class EndpointTargetWork {
        final HttpRequest baseRequest;
        final List<String> paramNames;

        EndpointTargetWork(HttpRequest baseRequest, List<String> paramNames) {
            this.baseRequest = baseRequest;
            this.paramNames = paramNames;
        }
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

            while (paused.get() && !cancelled.get()) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }

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

        String detectionIndicator;
        ValidationSeverity severity;

        // Evaluate behavior based on response status and body reflection (signature matching removed)
        if (statusCode >= 500) {
            detectionIndicator = "Server error " + statusCode + " triggered";
            severity = ValidationSeverity.HIGH;
        } else if (payload.length() > 2 && body != null && body.contains(payload)) {
            detectionIndicator = "Payload reflected in response body";
            severity = ValidationSeverity.MEDIUM;
        } else if (statusCode == 400 || statusCode == 422) {
            detectionIndicator = "Handled: status " + statusCode;
            severity = ValidationSeverity.LOW;
        } else if (statusCode >= 200 && statusCode < 300) {
            detectionIndicator = "Normal response " + statusCode + " (" + length + " bytes)";
            severity = ValidationSeverity.INFO;
        } else {
            detectionIndicator = "Status " + statusCode + " (" + length + " bytes)";
            severity = ValidationSeverity.INFO;
        }

        return new InputValidationTestResult_littlespidy(
                id, method, targetUrl, paramName, category, payload,
                statusCode, length, detectionIndicator, severity, message
        );
    }
}
