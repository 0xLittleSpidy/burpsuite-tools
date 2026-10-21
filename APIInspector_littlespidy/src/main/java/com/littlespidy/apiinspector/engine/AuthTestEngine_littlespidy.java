// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.model.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Multi-threaded execution engine for running authentication and authorization
 * tests across imported API endpoints.
 */
public class AuthTestEngine_littlespidy {

    private final Http http;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private ExecutorService executor;

    public AuthTestEngine_littlespidy(Http http) {
        this.http = http;
    }

    public synchronized boolean isRunning() {
        return running.get();
    }

    public synchronized void stopTesting() {
        if (running.get()) {
            cancelled.set(true);
            if (executor != null && !executor.isShutdown()) {
                executor.shutdownNow();
            }
        }
    }

    /**
     * Executes authentication tests for a list of test targets.
     * Each target pairs a collection and an endpoint with an active auth profile.
     */
    public synchronized void startTesting(
            List<EndpointTestTarget> targets,
            int threadCount,
            int delayMs,
            boolean runUnauthenticatedComparison,
            AuthTestProgressListener_littlespidy listener) {

        if (running.get()) {
            if (listener != null) {
                listener.onTestError("An authentication testing run is already in progress.");
            }
            return;
        }

        if (targets == null || targets.isEmpty()) {
            if (listener != null) {
                listener.onTestError("No endpoints selected for authentication testing.");
            }
            return;
        }

        running.set(true);
        cancelled.set(false);

        Thread coordinator = new Thread(() -> {
            try {
                int totalCount = targets.size();
                if (listener != null) {
                    listener.onTestStarted(totalCount);
                }

                int threads = Math.max(1, Math.min(threadCount, 20));
                executor = Executors.newFixedThreadPool(threads);
                AtomicInteger completedCount = new AtomicInteger(0);

                for (EndpointTestTarget target : targets) {
                    if (cancelled.get()) break;

                    executor.submit(() -> {
                        if (cancelled.get()) return;

                        if (delayMs > 0) {
                            try {
                                Thread.sleep(delayMs);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                return;
                            }
                        }

                        if (cancelled.get()) return;

                        AuthTestResult_littlespidy result = executeSingleTarget(target, runUnauthenticatedComparison);
                        int count = completedCount.incrementAndGet();

                        if (listener != null) {
                            listener.onEndpointResult(result, count, totalCount);
                        }
                    });
                }

                executor.shutdown();
                try {
                    executor.awaitTermination(2, TimeUnit.HOURS);
                } catch (InterruptedException e) {
                    cancelled.set(true);
                    executor.shutdownNow();
                    Thread.currentThread().interrupt();
                }

                running.set(false);
                if (listener != null) {
                    listener.onTestFinished(cancelled.get(), completedCount.get());
                }

            } catch (Exception ex) {
                running.set(false);
                if (listener != null) {
                    listener.onTestError("Test execution error: " + ex.getMessage());
                    listener.onTestFinished(cancelled.get(), 0);
                }
            }
        }, "APIInspector-AuthTest-Coordinator");

        coordinator.setDaemon(true);
        coordinator.start();
    }

    private AuthTestResult_littlespidy executeSingleTarget(EndpointTestTarget target, boolean runUnauthComparison) {
        ImportedCollection_littlespidy col = target.collection;
        DiscoveredEndpoint_littlespidy ep = target.endpoint;
        AuthProfile_littlespidy profile = target.profile;

        AuthTestResult_littlespidy result = new AuthTestResult_littlespidy();
        result.setCollectionId(col != null ? col.getId() : "");
        result.setCollectionName(col != null ? col.getName() : "Collection");
        result.setMethod(ep.getMethod());
        result.setPath(ep.getPath());
        result.setProfileId(profile != null ? profile.getId() : "unauthenticated");
        result.setProfileName(profile != null ? profile.getName() : "Unauthenticated request");
        result.setTimestamp(System.currentTimeMillis());

        String targetBaseUrl = (col != null && col.getTargetBaseUrl() != null && !col.getTargetBaseUrl().isBlank())
                ? col.getTargetBaseUrl()
                : "https://localhost";

        // Handle standalone unauthenticated test configuration
        if (profile == null) {
            try {
                HttpRequest unauthReq = buildRequest(targetBaseUrl, ep, null, false);
                result.setFullUrl(unauthReq.url());
                if (unauthReq.toByteArray() != null) {
                    result.setAuthRequestBytes(unauthReq.toByteArray().getBytes());
                    result.setUnauthRequestBytes(unauthReq.toByteArray().getBytes());
                }

                if (http != null) {
                    long startUnauth = System.currentTimeMillis();
                    HttpRequestResponse unauthReqResp = http.sendRequest(unauthReq);
                    long latency = System.currentTimeMillis() - startUnauth;
                    result.setAuthLatencyMs(latency);
                    result.setUnauthLatencyMs(latency);

                    if (unauthReqResp != null && unauthReqResp.hasResponse()) {
                        HttpResponse unauthResp = unauthReqResp.response();
                        result.setAuthStatusCode(unauthResp.statusCode());
                        result.setUnauthStatusCode(unauthResp.statusCode());
                        int len = unauthResp.body() != null ? unauthResp.body().length() : 0;
                        result.setAuthResponseLength(len);
                        result.setUnauthResponseLength(len);
                        if (unauthResp.toByteArray() != null) {
                            result.setAuthResponseBytes(unauthResp.toByteArray().getBytes());
                            result.setUnauthResponseBytes(unauthResp.toByteArray().getBytes());
                        }
                    }
                }

                int code = result.getAuthStatusCode();
                if (code == 0) {
                    result.setOutcome(AuthTestOutcome_littlespidy.NETWORK_ERROR);
                } else if (code >= 200 && code < 300) {
                    result.setOutcome(AuthTestOutcome_littlespidy.UNAUTHENTICATED_ACCESSIBLE);
                } else if (code == 401 || code == 403) {
                    result.setOutcome(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY);
                } else if (code >= 500) {
                    result.setOutcome(AuthTestOutcome_littlespidy.SERVER_ERROR);
                } else {
                    result.setOutcome(AuthTestOutcome_littlespidy.CLIENT_ERROR);
                }
            } catch (Exception ex) {
                result.setOutcome(AuthTestOutcome_littlespidy.NETWORK_ERROR);
                result.setErrorMessage("Unauthenticated request error: " + ex.getMessage());
            }
            return result;
        }

        // 1. Build and execute Authenticated Request
        HttpRequest authReq = null;
        try {
            authReq = buildRequest(targetBaseUrl, ep, profile, true);
            result.setFullUrl(authReq.url());
            if (authReq.toByteArray() != null) {
                result.setAuthRequestBytes(authReq.toByteArray().getBytes());
            }

            if (http != null) {
                long startAuth = System.currentTimeMillis();
                HttpRequestResponse authReqResp = http.sendRequest(authReq);
                result.setAuthLatencyMs(System.currentTimeMillis() - startAuth);

                if (authReqResp != null && authReqResp.hasResponse()) {
                    HttpResponse authResp = authReqResp.response();
                    result.setAuthStatusCode(authResp.statusCode());
                    result.setAuthResponseLength(authResp.body() != null ? authResp.body().length() : 0);
                    if (authResp.toByteArray() != null) {
                        result.setAuthResponseBytes(authResp.toByteArray().getBytes());
                    }
                }
            }
        } catch (Exception ex) {
            result.setOutcome(AuthTestOutcome_littlespidy.NETWORK_ERROR);
            result.setErrorMessage("Authenticated request error: " + ex.getMessage());
            return result;
        }

        // 2. Build and execute Unauthenticated Comparison Request if requested
        boolean shouldRunUnauth = runUnauthComparison && (profile == null || profile.isTestUnauthenticatedComparison());
        if (shouldRunUnauth && !cancelled.get()) {
            try {
                HttpRequest unauthReq = buildRequest(targetBaseUrl, ep, profile, false);
                if (unauthReq.toByteArray() != null) {
                    result.setUnauthRequestBytes(unauthReq.toByteArray().getBytes());
                }

                if (http != null) {
                    long startUnauth = System.currentTimeMillis();
                    HttpRequestResponse unauthReqResp = http.sendRequest(unauthReq);
                    result.setUnauthLatencyMs(System.currentTimeMillis() - startUnauth);

                    if (unauthReqResp != null && unauthReqResp.hasResponse()) {
                        HttpResponse unauthResp = unauthReqResp.response();
                        result.setUnauthStatusCode(unauthResp.statusCode());
                        result.setUnauthResponseLength(unauthResp.body() != null ? unauthResp.body().length() : 0);
                        if (unauthResp.toByteArray() != null) {
                            result.setUnauthResponseBytes(unauthResp.toByteArray().getBytes());
                        }
                    }
                }
            } catch (Exception ex) {
                result.setErrorMessage("Unauthenticated comparison request error: " + ex.getMessage());
            }
        }

        // 3. Classify outcome
        classifyOutcome(result, shouldRunUnauth);
        return result;
    }

    private void classifyOutcome(AuthTestResult_littlespidy result, boolean unauthWasRun) {
        int authCode = result.getAuthStatusCode();
        int unauthCode = result.getUnauthStatusCode();

        if (authCode == 0) {
            result.setOutcome(AuthTestOutcome_littlespidy.NETWORK_ERROR);
            return;
        }

        if (unauthWasRun && unauthCode > 0) {
            if (authCode >= 200 && authCode < 300) {
                if (unauthCode >= 200 && unauthCode < 300) {
                    result.setOutcome(AuthTestOutcome_littlespidy.UNAUTHENTICATED_ACCESSIBLE);
                } else if (unauthCode == 401 || unauthCode == 403) {
                    result.setOutcome(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY);
                } else {
                    result.setOutcome(AuthTestOutcome_littlespidy.SUCCESS);
                }
                return;
            }
        }

        if (authCode == 401 || authCode == 403) {
            result.setOutcome(AuthTestOutcome_littlespidy.AUTH_REJECTED);
        } else if (authCode >= 200 && authCode < 300) {
            result.setOutcome(AuthTestOutcome_littlespidy.SUCCESS);
        } else if (authCode >= 400 && authCode < 500) {
            result.setOutcome(AuthTestOutcome_littlespidy.CLIENT_ERROR);
        } else if (authCode >= 500) {
            result.setOutcome(AuthTestOutcome_littlespidy.SERVER_ERROR);
        } else {
            result.setOutcome(AuthTestOutcome_littlespidy.SUCCESS);
        }
    }

    public static HttpRequest buildRequest(
            String targetBaseUrl,
            DiscoveredEndpoint_littlespidy ep,
            AuthProfile_littlespidy profile,
            boolean includeAuth) {

        String path = ep.getPath() != null ? ep.getPath() : "/";

        // Replace path variables
        if (ep.getPathParams() != null && !ep.getPathParams().isEmpty()) {
            for (Map.Entry<String, String> entry : ep.getPathParams().entrySet()) {
                String varKey = "{" + entry.getKey() + "}";
                String val = (entry.getValue() != null && !entry.getValue().isBlank()) ? entry.getValue() : "1";
                path = path.replace(varKey, val);
            }
        }

        // Construct base URL string
        StringBuilder urlBuilder = new StringBuilder();
        if (path.startsWith("http://") || path.startsWith("https://")) {
            urlBuilder.append(path);
        } else {
            String base = targetBaseUrl != null ? targetBaseUrl.trim() : "https://localhost";
            if (base.endsWith("/") && path.startsWith("/")) {
                urlBuilder.append(base).append(path.substring(1));
            } else if (!base.endsWith("/") && !path.startsWith("/")) {
                urlBuilder.append(base).append("/").append(path);
            } else {
                urlBuilder.append(base).append(path);
            }
        }

        // Query parameters
        StringBuilder queryBuilder = new StringBuilder();
        if (ep.getQueryParams() != null && !ep.getQueryParams().isEmpty()) {
            for (Map.Entry<String, String> q : ep.getQueryParams().entrySet()) {
                if (queryBuilder.length() > 0) queryBuilder.append("&");
                queryBuilder.append(urlEncode(q.getKey())).append("=").append(urlEncode(q.getValue()));
            }
        }

        // If auth profile injects API key via query parameter
        if (includeAuth && profile != null && profile.getAuthType() == AuthType_littlespidy.API_KEY
                && profile.getApiKeyLocation() == ApiKeyLocation_littlespidy.QUERY_PARAM) {
            if (!profile.getApiKeyName().isBlank()) {
                if (queryBuilder.length() > 0) queryBuilder.append("&");
                queryBuilder.append(urlEncode(profile.getApiKeyName())).append("=").append(urlEncode(profile.getApiKeyValue()));
            }
        }

        if (queryBuilder.length() > 0) {
            if (urlBuilder.indexOf("?") >= 0) {
                urlBuilder.append("&").append(queryBuilder);
            } else {
                urlBuilder.append("?").append(queryBuilder);
            }
        }

        String fullUrl = urlBuilder.toString();
        HttpRequest request = null;
        try {
            HttpRequest fromUrl = HttpRequest.httpRequestFromUrl(fullUrl);
            if (fromUrl != null) {
                request = fromUrl.withMethod(ep.getMethod());
            }
        } catch (Throwable ignored) {
        }
        if (request == null) {
            request = createFallbackHttpRequest(fullUrl, ep.getMethod());
        }

        // Custom headers from endpoint definition
        if (ep.getHeaders() != null && !ep.getHeaders().isEmpty()) {
            for (Map.Entry<String, String> h : ep.getHeaders().entrySet()) {
                request = request.withHeader(h.getKey(), h.getValue());
            }
        }

        // Request Body
        String method = ep.getMethod() != null ? ep.getMethod().toUpperCase(Locale.ROOT) : "GET";
        if (("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))
                && ep.getRequestBodySample() != null && !ep.getRequestBodySample().isBlank()) {
            request = request.withBody(ep.getRequestBodySample());
            if (!request.hasHeader("Content-Type")) {
                request = request.withHeader("Content-Type", ep.getContentType() != null ? ep.getContentType() : "application/json");
            }
        }

        // Apply Authentication Profile if requested
        if (includeAuth && profile != null) {
            switch (profile.getAuthType()) {
                case BEARER_TOKEN:
                    if (!profile.getBearerToken().isBlank()) {
                        request = request.withHeader("Authorization", "Bearer " + profile.getBearerToken().trim());
                    }
                    break;
                case API_KEY:
                    if (profile.getApiKeyLocation() == ApiKeyLocation_littlespidy.HEADER && !profile.getApiKeyName().isBlank()) {
                        request = request.withHeader(profile.getApiKeyName().trim(), profile.getApiKeyValue().trim());
                    }
                    break;
                case BASIC_AUTH:
                    request = request.withHeader("Authorization", profile.getBasicAuthHeaderValue());
                    break;
                case COOKIE:
                    if (!profile.getCookieName().isBlank()) {
                        String cookiePair = profile.getCookieName().trim() + "=" + profile.getCookieValue().trim();
                        if (request.hasHeader("Cookie")) {
                            String existing = request.headerValue("Cookie");
                            request = request.withHeader("Cookie", existing + "; " + cookiePair);
                        } else {
                            request = request.withHeader("Cookie", cookiePair);
                        }
                    }
                    break;
                case CUSTOM_HEADER:
                    if (!profile.getCustomHeaderName().isBlank()) {
                        request = request.withHeader(profile.getCustomHeaderName().trim(), profile.getCustomHeaderValue().trim());
                    }
                    break;
            }
        }

        return request;
    }

    private static String urlEncode(String s) {
        if (s == null) return "";
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static HttpRequest createFallbackHttpRequest(String url, String method) {
        return createFallbackHttpRequest(url, method, new LinkedHashMap<>(), "");
    }

    private static HttpRequest createFallbackHttpRequest(String url, String method, Map<String, String> initialHeaders, String body) {
        Map<String, String> headers = initialHeaders != null ? new LinkedHashMap<>(initialHeaders) : new LinkedHashMap<>();
        return (HttpRequest) java.lang.reflect.Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, invokedMethod, args) -> {
                    String mName = invokedMethod.getName();
                    if ("method".equals(mName)) return method != null ? method : "GET";
                    if ("url".equals(mName)) return url != null ? url : "https://localhost/";
                    if ("path".equals(mName)) {
                        int idx = url.indexOf("://");
                        if (idx >= 0) {
                            int slash = url.indexOf('/', idx + 3);
                            return slash >= 0 ? url.substring(slash) : "/";
                        }
                        return url;
                    }
                    if ("withMethod".equals(mName) && args.length == 1) {
                        return createFallbackHttpRequest(url, (String) args[0], new LinkedHashMap<>(headers), body);
                    }
                    if ("withPath".equals(mName) && args.length == 1) {
                        return createFallbackHttpRequest((String) args[0], method, new LinkedHashMap<>(headers), body);
                    }
                    if ("headerValue".equals(mName) && args.length == 1) {
                        String target = (String) args[0];
                        for (Map.Entry<String, String> e : headers.entrySet()) {
                            if (e.getKey().equalsIgnoreCase(target)) return e.getValue();
                        }
                        return null;
                    }
                    if ("hasHeader".equals(mName) && args.length == 1) {
                        String target = (String) args[0];
                        for (String k : headers.keySet()) {
                            if (k.equalsIgnoreCase(target)) return true;
                        }
                        return false;
                    }
                    if ("withHeader".equals(mName) && args.length == 2) {
                        Map<String, String> next = new LinkedHashMap<>(headers);
                        next.put((String) args[0], (String) args[1]);
                        return createFallbackHttpRequest(url, method, next, body);
                    }
                    if ("withRemovedHeader".equals(mName) && args.length == 1) {
                        String toRemove = (String) args[0];
                        Map<String, String> next = new LinkedHashMap<>();
                        for (Map.Entry<String, String> e : headers.entrySet()) {
                            if (!e.getKey().equalsIgnoreCase(toRemove)) {
                                next.put(e.getKey(), e.getValue());
                            }
                        }
                        return createFallbackHttpRequest(url, method, next, body);
                    }
                    if ("withBody".equals(mName) && args.length == 1) {
                        return createFallbackHttpRequest(url, method, new LinkedHashMap<>(headers), (String) args[0]);
                    }
                    if ("bodyToString".equals(mName)) return body != null ? body : "";
                    if ("toByteArray".equals(mName)) {
                        byte[] reqBytes = ((method != null ? method : "GET") + " " + url + " HTTP/1.1\r\n\r\n" + (body != null ? body : "")).getBytes(StandardCharsets.UTF_8);
                        return burp.api.montoya.core.ByteArray.byteArray(reqBytes);
                    }
                    if ("httpService".equals(mName)) {
                        String host = "localhost";
                        int port = 443;
                        boolean secure = true;
                        try {
                            java.net.URI u = java.net.URI.create(url);
                            if (u.getHost() != null) host = u.getHost();
                            secure = "https".equalsIgnoreCase(u.getScheme());
                            port = u.getPort() > 0 ? u.getPort() : (secure ? 443 : 80);
                        } catch (Exception ignored) {}
                        final String fHost = host;
                        final int fPort = port;
                        final boolean fSecure = secure;
                        return (burp.api.montoya.http.HttpService) java.lang.reflect.Proxy.newProxyInstance(
                                burp.api.montoya.http.HttpService.class.getClassLoader(),
                                new Class<?>[]{burp.api.montoya.http.HttpService.class},
                                (p, m, a) -> {
                                    if ("host".equals(m.getName())) return fHost;
                                    if ("port".equals(m.getName())) return fPort;
                                    if ("secure".equals(m.getName())) return fSecure;
                                    return null;
                                }
                        );
                    }
                    return null;
                }
        );
    }

    /**
     * Data carrier linking an endpoint to its parent collection and resolved auth profile.
     */
    public static class EndpointTestTarget {
        public final ImportedCollection_littlespidy collection;
        public final DiscoveredEndpoint_littlespidy endpoint;
        public final AuthProfile_littlespidy profile;

        public EndpointTestTarget(
                ImportedCollection_littlespidy collection,
                DiscoveredEndpoint_littlespidy endpoint,
                AuthProfile_littlespidy profile) {
            this.collection = collection;
            this.endpoint = endpoint;
            this.profile = profile;
        }
    }
}
