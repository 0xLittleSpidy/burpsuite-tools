// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.PostToGetTestResult_littlespidy;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Testing engine for automated HTTP method tampering (POST-to-GET conversion).
 * Converts POST request bodies into URL query parameters, sends GET probes,
 * and analyzes behavior differences against the baseline POST.
 */
public class PostToGetEngine_littlespidy {

    private final MontoyaApi api;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private ExecutorService threadPool;

    private static final Pattern JSON_KEY_VALUE = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"[^\"]*\"|\\d+|true|false|null)");

    public PostToGetEngine_littlespidy(MontoyaApi api) {
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

    public void executeEndpointsTestsAsync(
            List<? extends EndpointSelectionItem_littlespidy> endpoints,
            String defaultTargetBaseUrl,
            AuthProfile_littlespidy profile,
            String customAuthHeader,
            int threadCount,
            int delayMs,
            PostToGetProgressListener_littlespidy listener) {

        cancelled.set(false);
        paused.set(false);
        int threads = Math.max(1, threadCount);
        this.threadPool = Executors.newFixedThreadPool(threads);

        Thread runner = new Thread(() -> {
            try {
                List<EndpointSelectionItem_littlespidy> activeEndpoints = new ArrayList<>();
                for (EndpointSelectionItem_littlespidy ep : endpoints) {
                    if (ep.selected) {
                        activeEndpoints.add(ep);
                    }
                }

                if (activeEndpoints.isEmpty()) {
                    if (listener != null) {
                        listener.onStatusUpdate("No endpoints selected for testing", 0, 0);
                        listener.onAllTestsCompleted();
                    }
                    return;
                }

                int total = activeEndpoints.size();
                AtomicInteger completedCount = new AtomicInteger(0);
                AtomicInteger idCounter = new AtomicInteger(1);

                for (EndpointSelectionItem_littlespidy item : activeEndpoints) {
                    if (cancelled.get()) break;

                    String baseUrl = (item.collection != null && item.collection.getTargetBaseUrl() != null && !item.collection.getTargetBaseUrl().isBlank())
                            ? item.collection.getTargetBaseUrl()
                            : (defaultTargetBaseUrl != null && !defaultTargetBaseUrl.isBlank() ? defaultTargetBaseUrl : "https://localhost");

                    HttpRequest baseRequest;
                    try {
                        baseRequest = AuthTestEngine_littlespidy.buildRequest(baseUrl, item.endpoint, profile, profile != null);
                    } catch (Exception ex) {
                        baseRequest = HttpRequest.httpRequestFromUrl(baseUrl + item.endpoint.getPath());
                    }

                    if (customAuthHeader != null && !customAuthHeader.isBlank() && customAuthHeader.contains(":")) {
                        String[] parts = customAuthHeader.split(":", 2);
                        baseRequest = baseRequest.withAddedHeader(parts[0].trim(), parts[1].trim());
                    }

                    if (baseRequest == null) {
                        completedCount.incrementAndGet();
                        continue;
                    }

                    // Dynamically resolve target base URL directly from request httpService
                    if (baseRequest.httpService() != null && baseRequest.httpService().host() != null) {
                        baseUrl = (baseRequest.httpService().secure() ? "https://" : "http://") + baseRequest.httpService().host();
                        if ((baseRequest.httpService().secure() && baseRequest.httpService().port() != 443) ||
                                (!baseRequest.httpService().secure() && baseRequest.httpService().port() != 80)) {
                            baseUrl += ":" + baseRequest.httpService().port();
                        }
                    }

                    final HttpRequest finalBaseRequest = baseRequest;
                    final EndpointSelectionItem_littlespidy finalItem = item;

                    threadPool.submit(() -> {
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

                            // 1. Send baseline POST request
                            HttpRequestResponse baselineReqResp = null;
                            if (api != null && api.http() != null) {
                                baselineReqResp = api.http().sendRequest(finalBaseRequest);
                            }

                            int origStatus = 0;
                            int origLen = 0;
                            if (baselineReqResp != null && baselineReqResp.hasResponse() && baselineReqResp.response() != null) {
                                origStatus = baselineReqResp.response().statusCode();
                                origLen = baselineReqResp.response().body().length();
                            }

                            // 2. Convert POST request to GET with query parameters
                            Map<String, String> bodyParams = extractBodyParameters(finalBaseRequest);
                            HttpRequest mutatedGetRequest = buildGetRequest(finalBaseRequest, bodyParams);

                            // 3. Send mutated GET request
                            HttpRequestResponse mutatedReqResp = null;
                            if (api != null && api.http() != null) {
                                mutatedReqResp = api.http().sendRequest(mutatedGetRequest);
                            }

                            int mutatedStatus = 0;
                            int mutatedLen = 0;
                            if (mutatedReqResp != null && mutatedReqResp.hasResponse() && mutatedReqResp.response() != null) {
                                mutatedStatus = mutatedReqResp.response().statusCode();
                                mutatedLen = mutatedReqResp.response().body().length();
                            }

                            // 4. Formulate query summary
                            StringBuilder qSummary = new StringBuilder();
                            int pCount = 0;
                            for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
                                if (pCount > 0) qSummary.append("&");
                                qSummary.append(entry.getKey()).append("=").append(entry.getValue());
                                pCount++;
                            }

                            // 5. Determine Verdict
                            String verdict = evaluateVerdict(origStatus, origLen, mutatedStatus, mutatedLen);

                            int currentId = idCounter.getAndIncrement();
                            String colId = finalItem.collection != null ? finalItem.collection.getId() : "";
                            String colName = finalItem.collection != null ? finalItem.collection.getName() : "Collection";
                            String fullUrl = mutatedGetRequest.url();

                            PostToGetTestResult_littlespidy result = new PostToGetTestResult_littlespidy(
                                    currentId, colId, colName, finalItem.endpoint.getPath(),
                                    fullUrl, finalBaseRequest.method(), "GET",
                                    qSummary.toString(), origStatus, mutatedStatus,
                                    origLen, mutatedLen, verdict,
                                    baselineReqResp, mutatedReqResp
                            );

                            int done = completedCount.incrementAndGet();
                            if (listener != null) {
                                listener.onPostToGetTestCompleted(result);
                                listener.onStatusUpdate("Executed " + done + "/" + total + " POST-to-GET tests", done, total);
                            }

                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        } catch (Exception ex) {
                            int done = completedCount.incrementAndGet();
                            if (listener != null) {
                                listener.onStatusUpdate("Error on endpoint: " + ex.getMessage(), done, total);
                            }
                        }
                    });
                }

                threadPool.shutdown();
                try {
                    threadPool.awaitTermination(2, TimeUnit.HOURS);
                } catch (InterruptedException ie) {
                    cancelled.set(true);
                    threadPool.shutdownNow();
                    Thread.currentThread().interrupt();
                }

                if (listener != null) {
                    listener.onAllTestsCompleted();
                }

            } catch (Exception ex) {
                if (listener != null) {
                    listener.onStatusUpdate("Execution stopped: " + ex.getMessage(), 0, 0);
                    listener.onAllTestsCompleted();
                }
            }
        }, "POST-to-GET-Runner_littlespidy");

        runner.setDaemon(true);
        runner.start();
    }

    public void executeRequestTestAsync(
            HttpRequest postRequest,
            int threadCount,
            int delayMs,
            PostToGetProgressListener_littlespidy listener) {

        cancelled.set(false);
        paused.set(false);
        this.threadPool = Executors.newFixedThreadPool(1);

        Thread runner = new Thread(() -> {
            try {
                if (postRequest == null) {
                    if (listener != null) {
                        listener.onStatusUpdate("No request specified", 0, 0);
                        listener.onAllTestsCompleted();
                    }
                    return;
                }

                while (paused.get() && !cancelled.get()) {
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }

                if (cancelled.get()) {
                    if (listener != null) listener.onAllTestsCompleted();
                    return;
                }

                if (delayMs > 0) {
                    Thread.sleep(delayMs);
                }

                // 1. Send baseline POST request
                HttpRequestResponse baselineReqResp = null;
                if (api != null && api.http() != null) {
                    baselineReqResp = api.http().sendRequest(postRequest);
                }

                int origStatus = 0;
                int origLen = 0;
                if (baselineReqResp != null && baselineReqResp.hasResponse() && baselineReqResp.response() != null) {
                    origStatus = baselineReqResp.response().statusCode();
                    origLen = baselineReqResp.response().body().length();
                }

                // 2. Convert POST request to GET with query parameters
                Map<String, String> bodyParams = extractBodyParameters(postRequest);
                HttpRequest mutatedGetRequest = buildGetRequest(postRequest, bodyParams);

                // 3. Send mutated GET request
                HttpRequestResponse mutatedReqResp = null;
                if (api != null && api.http() != null) {
                    mutatedReqResp = api.http().sendRequest(mutatedGetRequest);
                }

                int mutatedStatus = 0;
                int mutatedLen = 0;
                if (mutatedReqResp != null && mutatedReqResp.hasResponse() && mutatedReqResp.response() != null) {
                    mutatedStatus = mutatedReqResp.response().statusCode();
                    mutatedLen = mutatedReqResp.response().body().length();
                }

                StringBuilder qSummary = new StringBuilder();
                int pCount = 0;
                for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
                    if (pCount > 0) qSummary.append("&");
                    qSummary.append(entry.getKey()).append("=").append(entry.getValue());
                    pCount++;
                }

                String verdict = evaluateVerdict(origStatus, origLen, mutatedStatus, mutatedLen);

                PostToGetTestResult_littlespidy result = new PostToGetTestResult_littlespidy(
                        1,
                        "",
                        "Direct Request",
                        postRequest.path(),
                        mutatedGetRequest.url(),
                        postRequest.method(),
                        "GET",
                        qSummary.toString(),
                        origStatus,
                        mutatedStatus,
                        origLen,
                        mutatedLen,
                        verdict,
                        baselineReqResp,
                        mutatedReqResp
                );

                if (listener != null) {
                    listener.onPostToGetTestCompleted(result);
                    listener.onStatusUpdate("Executed 1/1 POST-to-GET test", 1, 1);
                    listener.onAllTestsCompleted();
                }

            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (Exception ex) {
                if (listener != null) {
                    listener.onStatusUpdate("Error executing test: " + ex.getMessage(), 1, 1);
                    listener.onAllTestsCompleted();
                }
            }
        }, "POST-to-GET-Single-Runner_littlespidy");

        runner.setDaemon(true);
        runner.start();
    }

    public static Map<String, String> extractBodyParameters(HttpRequest request) {
        Map<String, String> params = new LinkedHashMap<>();
        if (request == null) return params;

        // 1. Parsed Montoya body parameters
        try {
            for (ParsedHttpParameter p : request.parameters()) {
                if (p.type() == HttpParameterType.BODY) {
                    params.put(p.name(), p.value() != null ? p.value() : "");
                }
            }
        } catch (Exception ignored) {}

        if (!params.isEmpty()) {
            return params;
        }

        // 2. Fallback to raw body parsing (JSON or form-urlencoded)
        String body = request.bodyToString();
        if (body != null && !body.isBlank()) {
            body = body.trim();
            if (body.startsWith("{") && body.endsWith("}")) {
                Matcher m = JSON_KEY_VALUE.matcher(body);
                while (m.find()) {
                    String key = m.group(1);
                    String val = m.group(2).trim();
                    if (val.startsWith("\"") && val.endsWith("\"") && val.length() >= 2) {
                        val = val.substring(1, val.length() - 1);
                    }
                    params.put(key, val);
                }
            } else if (body.contains("=")) {
                String[] pairs = body.split("&");
                for (String pair : pairs) {
                    String[] kv = pair.split("=", 2);
                    if (kv.length == 2) {
                        try {
                            String k = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                            String v = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                            params.put(k, v);
                        } catch (Exception e) {
                            params.put(kv[0], kv[1]);
                        }
                    }
                }
            }
        }

        return params;
    }

    public static HttpRequest buildGetRequest(HttpRequest postRequest, Map<String, String> bodyParams) {
        if (postRequest == null) return null;

        HttpRequest req = postRequest.withMethod("GET");

        // Clean body and body-related headers
        req = req.withBody("");
        List<burp.api.montoya.http.message.HttpHeader> headers = req.headers();
        for (burp.api.montoya.http.message.HttpHeader h : headers) {
            String nameLower = h.name().toLowerCase(Locale.ROOT);
            if (nameLower.equals("content-length") || nameLower.equals("content-type")) {
                req = req.withRemovedHeader(h);
            }
        }

        // Append body parameters as URL query parameters
        if (bodyParams != null && !bodyParams.isEmpty()) {
            StringBuilder qs = new StringBuilder();
            for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
                if (qs.length() > 0) qs.append("&");
                try {
                    qs.append(java.net.URLEncoder.encode(entry.getKey(), java.nio.charset.StandardCharsets.UTF_8.name()))
                            .append("=")
                            .append(java.net.URLEncoder.encode(entry.getValue(), java.nio.charset.StandardCharsets.UTF_8.name()));
                } catch (Exception ignored) {
                    qs.append(entry.getKey()).append("=").append(entry.getValue());
                }
            }
            String currentPath = req.path();
            if (currentPath == null) currentPath = "/";
            String sep = currentPath.contains("?") ? "&" : "?";
            req = req.withPath(currentPath + sep + qs.toString());
        }

        return req;
    }

    public static String evaluateVerdict(int origStatus, int origLen, int mutatedStatus, int mutatedLen) {
        if (mutatedStatus == 0) {
            return "No Response / Network Error";
        }
        if (origStatus == mutatedStatus && mutatedStatus >= 200 && mutatedStatus < 300) {
            return "Method Tampering Accepted (Status Match " + mutatedStatus + ")";
        }
        if (mutatedStatus >= 200 && mutatedStatus < 300) {
            return "GET Accepted (Status " + mutatedStatus + " OK)";
        }
        if (mutatedStatus == 405) {
            return "Protected (405 Method Not Allowed)";
        }
        if (mutatedStatus == 401 || mutatedStatus == 403) {
            return "Auth Enforced (Status " + mutatedStatus + ")";
        }
        if (mutatedStatus >= 500) {
            return "Server Error (Status " + mutatedStatus + ")";
        }
        return "Status " + mutatedStatus + " (Diff " + (mutatedLen - origLen) + "B)";
    }
}
