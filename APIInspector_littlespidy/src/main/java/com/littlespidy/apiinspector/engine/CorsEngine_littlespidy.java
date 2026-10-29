// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.model.CorsTechnique_littlespidy;
import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy;
import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy.CorsSeverity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Execution engine for CORS bypass techniques using the Montoya API.
 */
public class CorsEngine_littlespidy {

    private final MontoyaApi api;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private ExecutorService threadPool;

    public CorsEngine_littlespidy(MontoyaApi api) {
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

    /**
     * Executes CORS tests asynchronously across the given techniques.
     */
    public void executeTestsAsync(
            HttpRequest baseRequest,
            String targetBaseUrl,
            String attackerDomain,
            List<CorsTechnique_littlespidy> techniques,
            int threadCount,
            int delayMs,
            CorsProgressListener_littlespidy listener) {

        cancelled.set(false);
        int threads = Math.max(1, threadCount);
        this.threadPool = Executors.newFixedThreadPool(threads);

        Thread runner = new Thread(() -> {
            try {
                List<CorsTechnique_littlespidy> activeTechniques = new ArrayList<>();
                for (CorsTechnique_littlespidy t : techniques) {
                    if (t.isEnabled()) {
                        activeTechniques.add(t);
                    }
                }

                int total = activeTechniques.size();
                AtomicInteger completedCount = new AtomicInteger(0);
                AtomicInteger idCounter = new AtomicInteger(1);

                String method = baseRequest.method();
                String path = baseRequest.path();
                String host = baseRequest.httpService() != null ? baseRequest.httpService().host() : "target";

                for (CorsTechnique_littlespidy tech : activeTechniques) {
                    if (cancelled.get()) break;

                    threadPool.submit(() -> {
                        if (cancelled.get()) return;

                        try {
                            if (delayMs > 0) {
                                Thread.sleep(delayMs);
                            }

                            String testedOrigin = tech.resolveOrigin(targetBaseUrl, attackerDomain);
                            HttpRequest modifiedRequest = createRequestWithOrigin(baseRequest, testedOrigin);

                            HttpRequestResponse responsePair = null;
                            if (api != null && api.http() != null) {
                                responsePair = api.http().sendRequest(modifiedRequest);
                            }

                            int currentId = idCounter.getAndIncrement();
                            CorsTestResult_littlespidy result = evaluateResponse(
                                    currentId, method, host, path, testedOrigin,
                                    tech.getName() + " - " + tech.getDescription(),
                                    modifiedRequest, responsePair
                            );

                            int done = completedCount.incrementAndGet();
                            if (listener != null) {
                                listener.onCorsTestCompleted(result);
                                listener.onStatusUpdate("Executed " + done + "/" + total + " CORS tests", done, total);
                            }
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        } catch (Exception ex) {
                            int done = completedCount.incrementAndGet();
                            if (listener != null) {
                                listener.onStatusUpdate("Error on vector: " + ex.getMessage(), done, total);
                            }
                        }
                    });
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
                    listener.onStatusUpdate("Test run finished with error: " + e.getMessage(), 0, 0);
                    listener.onAllTestsCompleted();
                }
            }
        }, "CORS-Engine-Runner_littlespidy");

        runner.setDaemon(true);
        runner.start();
    }

    public static HttpRequest createRequestWithOrigin(HttpRequest baseRequest, String origin) {
        if (baseRequest == null) return null;

        // Remove existing Origin headers and add new Origin header
        HttpRequest req = baseRequest;
        List<HttpHeader> headers = req.headers();
        for (HttpHeader h : headers) {
            if (h.name().equalsIgnoreCase("Origin")) {
                req = req.withRemovedHeader(h);
            }
        }
        return req.withAddedHeader("Origin", origin);
    }

    public static CorsTestResult_littlespidy evaluateResponse(
            int id, String method, String host, String path,
            String testedOrigin, String description,
            HttpRequest sentRequest, HttpRequestResponse message) {

        if (message == null || !message.hasResponse()) {
            return new CorsTestResult_littlespidy(
                    id, method, host, path, testedOrigin, description, "",
                    false, 0, 0, CorsSeverity.INFO, message
            );
        }

        HttpResponse response = message.response();
        int statusCode = response.statusCode();
        int length = response.body().length();
        String acao = "";
        boolean acac = false;

        for (HttpHeader header : response.headers()) {
            String lower = header.name().toLowerCase(Locale.ROOT);
            if (lower.equals("access-control-allow-origin")) {
                acao = header.value() != null ? header.value().trim() : "";
            } else if (lower.equals("access-control-allow-credentials")) {
                String val = header.value() != null ? header.value().trim() : "";
                if ("true".equalsIgnoreCase(val)) {
                    acac = true;
                }
            }
        }

        CorsSeverity severity = CorsSeverity.SECURE;
        boolean originReflected = !acao.isEmpty() && (acao.equalsIgnoreCase(testedOrigin) ||
                (!testedOrigin.equals("null") && acao.replace(" ", "").contains(testedOrigin.replace(" ", ""))));

        if (originReflected && acac) {
            severity = CorsSeverity.HIGH;
        } else if (testedOrigin.equals("null") && acao.equalsIgnoreCase("null") && acac) {
            severity = CorsSeverity.HIGH;
        } else if (originReflected) {
            severity = CorsSeverity.MEDIUM;
        } else if (acao.equals("*") && acac) {
            severity = CorsSeverity.HIGH;
        } else if (acao.equals("*")) {
            severity = CorsSeverity.LOW;
        } else if (!acao.isEmpty()) {
            severity = CorsSeverity.LOW;
        } else {
            severity = CorsSeverity.INFO;
        }

        return new CorsTestResult_littlespidy(
                id, method, host, path, testedOrigin, description, acao,
                acac, statusCode, length, severity, message
        );
    }
}
