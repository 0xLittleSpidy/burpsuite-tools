// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiefinder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.sessionexpiration.engine.SessionVerifier;

import javax.swing.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Systematic isolation and fuzzing engine that identifies session cookies,
 * authorization headers, and custom authentication tokens by systematically
 * removing credentials one-by-one and comparing against baseline and unauthenticated responses.
 *
 * @author littlespidy
 */
public class CookieFinderEngine {

    private final MontoyaApi api;
    private final ExecutorService executor;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    private static final Set<String> STANDARD_AUTH_HEADERS = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    static {
        STANDARD_AUTH_HEADERS.add("Authorization");
        STANDARD_AUTH_HEADERS.add("Proxy-Authorization");
        STANDARD_AUTH_HEADERS.add("X-Access-Token");
        STANDARD_AUTH_HEADERS.add("X-Auth-Token");
        STANDARD_AUTH_HEADERS.add("X-Authorization");
        STANDARD_AUTH_HEADERS.add("X-API-Key");
        STANDARD_AUTH_HEADERS.add("ApiKey");
        STANDARD_AUTH_HEADERS.add("Api-Key");
        STANDARD_AUTH_HEADERS.add("Token");
        STANDARD_AUTH_HEADERS.add("Bearer");
        STANDARD_AUTH_HEADERS.add("X-Session-ID");
        STANDARD_AUTH_HEADERS.add("X-Session-Token");
        STANDARD_AUTH_HEADERS.add("X-User-Token");
        STANDARD_AUTH_HEADERS.add("X-CSRF-Token");
        STANDARD_AUTH_HEADERS.add("X-XSRF-Token");
    }

    public interface ExecutionListener {
        void onTestStarted(int totalTests);
        void onResultAvailable(FinderResult result);
        void onFinished(List<FinderResult> allResults, Set<String> identifiedSessionTokens);
        void onError(String errorMessage);
    }

    public CookieFinderEngine(MontoyaApi api) {
        this.api = api;
        AtomicInteger count = new AtomicInteger(1);
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "CookieFinderEngine-" + count.getAndIncrement());
            t.setDaemon(true);
            return t;
        });
    }

    public void cancel() {
        cancelled.set(true);
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    /**
     * Executes the systematic cookie and authorization header isolation workflow.
     */
    public void startAnalysis(HttpRequest originalRequest,
                              String customHeadersInput,
                              boolean includeAnonymous,
                              boolean includeGroupTests,
                              ExecutionListener listener) {
        cancelled.set(false);

        executor.submit(() -> {
            try {
                if (originalRequest == null) {
                    notifyError(listener, "No target request provided.");
                    return;
                }

                // 1. Extract Cookies from Cookie: header
                Map<String, String> cookies = parseCookies(originalRequest);

                // 2. Identify Standard Auth Headers present in request
                List<HttpHeader> authHeadersPresent = new ArrayList<>();
                for (HttpHeader h : originalRequest.headers()) {
                    if (STANDARD_AUTH_HEADERS.contains(h.name())) {
                        authHeadersPresent.add(h);
                    }
                }

                // 3. Identify User-Specified Custom Headers present in request
                Set<String> customHeaderNames = parseCustomHeaderNames(customHeadersInput);
                List<HttpHeader> customHeadersPresent = new ArrayList<>();
                for (HttpHeader h : originalRequest.headers()) {
                    if (customHeaderNames.contains(h.name()) && !STANDARD_AUTH_HEADERS.contains(h.name())) {
                        customHeadersPresent.add(h);
                    }
                }

                int totalTests = 1 // Baseline
                        + (includeAnonymous ? 1 : 0)
                        + cookies.size()
                        + authHeadersPresent.size()
                        + customHeadersPresent.size()
                        + (includeGroupTests && !cookies.isEmpty() ? 1 : 0)
                        + (includeGroupTests && (!authHeadersPresent.isEmpty() || !customHeadersPresent.isEmpty()) ? 1 : 0);

                notifyStarted(listener, totalTests);

                List<FinderResult> results = new ArrayList<>();
                Set<String> sessionTokens = new LinkedHashSet<>();
                AtomicInteger testId = new AtomicInteger(1);

                // ── STEP 0: Authenticated Baseline Request ──────────────────
                api.logging().logToOutput("[CookieFinder] Sending authenticated baseline request...");
                long startBase = System.currentTimeMillis();
                HttpRequestResponse baselineRR = api.http().sendRequest(originalRequest);
                long durBase = System.currentTimeMillis() - startBase;

                if (baselineRR == null || !baselineRR.hasResponse()) {
                    notifyError(listener, "Failed to establish baseline: no response received from target.");
                    return;
                }

                HttpResponse baseResp = baselineRR.response();
                int baseStatus = baseResp.statusCode();
                long baseLen = baseResp.toByteArray().length();

                FinderResult baseResult = new FinderResult(
                        testId.getAndIncrement(),
                        "[Baseline] Authenticated",
                        FinderResult.TestType.BASELINE,
                        "Full Authenticated Request",
                        baseStatus,
                        baseLen,
                        0,
                        "🎯 Baseline Reference",
                        "Authenticated reference response (" + baseStatus + ", " + baseLen + " bytes)",
                        durBase,
                        baselineRR,
                        false
                );
                results.add(baseResult);
                notifyResult(listener, baseResult);

                if (cancelled.get()) {
                    notifyFinished(listener, results, sessionTokens);
                    return;
                }

                // ── STEP 1: Anonymous Benchmark (All Auth/Cookies Removed) ──
                HttpResponse anonResp = null;
                long anonLen = -1;
                if (includeAnonymous) {
                    HttpRequest anonReq = stripAllAuthAndCookies(originalRequest, customHeaderNames);
                    long startAnon = System.currentTimeMillis();
                    HttpRequestResponse anonRR = api.http().sendRequest(anonReq);
                    long durAnon = System.currentTimeMillis() - startAnon;

                    if (anonRR != null && anonRR.hasResponse()) {
                        anonResp = anonRR.response();
                        anonLen = anonResp.toByteArray().length();
                        long delta = anonLen - baseLen;

                        FinderResult anonResult = new FinderResult(
                                testId.getAndIncrement(),
                                "[Anonymous] All Stripped",
                                FinderResult.TestType.ANONYMOUS,
                                "All cookies & auth headers removed",
                                anonResp.statusCode(),
                                anonLen,
                                delta,
                                "🔒 Anonymous Benchmark",
                                "Unauthenticated control benchmark (" + anonResp.statusCode() + ", " + anonLen + " bytes)",
                                durAnon,
                                anonRR,
                                false
                        );
                        results.add(anonResult);
                        notifyResult(listener, anonResult);
                    }
                }

                if (cancelled.get()) {
                    notifyFinished(listener, results, sessionTokens);
                    return;
                }

                // ── STEP 2: Systematic Single Cookie Removal ─────────────────
                for (Map.Entry<String, String> entry : cookies.entrySet()) {
                    if (cancelled.get()) break;

                    String cookieName = entry.getKey();
                    String cookieVal = entry.getValue();
                    HttpRequest testReq = removeSingleCookie(originalRequest, cookieName, cookies);

                    long startProbe = System.currentTimeMillis();
                    HttpRequestResponse probeRR = api.http().sendRequest(testReq);
                    long durProbe = System.currentTimeMillis() - startProbe;

                    FinderResult result = evaluateTest(
                            testId.getAndIncrement(),
                            "Cookie: " + cookieName,
                            FinderResult.TestType.COOKIE,
                            previewValue(cookieVal),
                            baseResp,
                            anonResp,
                            probeRR,
                            durProbe
                    );

                    if (result.isSessionToken()) {
                        sessionTokens.add("Cookie: " + cookieName);
                    }
                    results.add(result);
                    notifyResult(listener, result);
                }

                // ── STEP 3: Systematic Standard Auth Header Removal ───────────
                for (HttpHeader authHdr : authHeadersPresent) {
                    if (cancelled.get()) break;

                    HttpRequest testReq = removeHeader(originalRequest, authHdr.name());

                    long startProbe = System.currentTimeMillis();
                    HttpRequestResponse probeRR = api.http().sendRequest(testReq);
                    long durProbe = System.currentTimeMillis() - startProbe;

                    FinderResult result = evaluateTest(
                            testId.getAndIncrement(),
                            "Header: " + authHdr.name(),
                            FinderResult.TestType.AUTH_HEADER,
                            previewValue(authHdr.value()),
                            baseResp,
                            anonResp,
                            probeRR,
                            durProbe
                    );

                    if (result.isSessionToken()) {
                        sessionTokens.add("Header: " + authHdr.name());
                    }
                    results.add(result);
                    notifyResult(listener, result);
                }

                // ── STEP 4: Systematic Custom Header Removal ──────────────────
                for (HttpHeader customHdr : customHeadersPresent) {
                    if (cancelled.get()) break;

                    HttpRequest testReq = removeHeader(originalRequest, customHdr.name());

                    long startProbe = System.currentTimeMillis();
                    HttpRequestResponse probeRR = api.http().sendRequest(testReq);
                    long durProbe = System.currentTimeMillis() - startProbe;

                    FinderResult result = evaluateTest(
                            testId.getAndIncrement(),
                            "Custom: " + customHdr.name(),
                            FinderResult.TestType.CUSTOM_HEADER,
                            previewValue(customHdr.value()),
                            baseResp,
                            anonResp,
                            probeRR,
                            durProbe
                    );

                    if (result.isSessionToken()) {
                        sessionTokens.add("Custom Header: " + customHdr.name());
                    }
                    results.add(result);
                    notifyResult(listener, result);
                }

                // ── STEP 5: Group Isolation Tests (Optional) ──────────────────
                if (includeGroupTests && !cancelled.get()) {
                    // Test A: All cookies removed (preserving auth headers)
                    if (!cookies.isEmpty()) {
                        HttpRequest noCookiesReq = removeAllCookieHeaders(originalRequest);
                        long startProbe = System.currentTimeMillis();
                        HttpRequestResponse probeRR = api.http().sendRequest(noCookiesReq);
                        long durProbe = System.currentTimeMillis() - startProbe;

                        FinderResult result = evaluateTest(
                                testId.getAndIncrement(),
                                "[Group] All Cookies Removed",
                                FinderResult.TestType.GROUP_ALL_COOKIES,
                                cookies.size() + " cookies stripped",
                                baseResp,
                                anonResp,
                                probeRR,
                                durProbe
                        );
                        results.add(result);
                        notifyResult(listener, result);
                    }

                    // Test B: All auth and custom headers removed (preserving cookies)
                    if (!authHeadersPresent.isEmpty() || !customHeadersPresent.isEmpty()) {
                        HttpRequest noAuthHeadersReq = originalRequest;
                        for (HttpHeader h : authHeadersPresent) {
                            noAuthHeadersReq = removeHeader(noAuthHeadersReq, h.name());
                        }
                        for (HttpHeader h : customHeadersPresent) {
                            noAuthHeadersReq = removeHeader(noAuthHeadersReq, h.name());
                        }

                        long startProbe = System.currentTimeMillis();
                        HttpRequestResponse probeRR = api.http().sendRequest(noAuthHeadersReq);
                        long durProbe = System.currentTimeMillis() - startProbe;

                        FinderResult result = evaluateTest(
                                testId.getAndIncrement(),
                                "[Group] All Auth Headers Removed",
                                FinderResult.TestType.GROUP_ALL_HEADERS,
                                (authHeadersPresent.size() + customHeadersPresent.size()) + " headers stripped",
                                baseResp,
                                anonResp,
                                probeRR,
                                durProbe
                        );
                        results.add(result);
                        notifyResult(listener, result);
                    }
                }

                notifyFinished(listener, results, sessionTokens);

            } catch (Exception ex) {
                api.logging().logToError("[CookieFinder] Error during analysis: " + ex.getMessage());
                notifyError(listener, "Analysis error: " + ex.getMessage());
            }
        });
    }

    /**
     * Evaluates a probe response against baseline and unauthenticated benchmarks.
     */
    private FinderResult evaluateTest(int id,
                                      String componentName,
                                      FinderResult.TestType type,
                                      String valuePreview,
                                      HttpResponse baseline,
                                      HttpResponse anonBenchmark,
                                      HttpRequestResponse probeRR,
                                      long durationMs) {
        if (probeRR == null || !probeRR.hasResponse()) {
            return new FinderResult(
                    id, componentName, type, valuePreview, 0, 0, 0,
                    "❌ Error / No Response", "Target failed to respond when " + componentName + " was removed",
                    durationMs, probeRR, false
            );
        }

        HttpResponse probe = probeRR.response();
        int probeStatus = probe.statusCode();
        int baseStatus = baseline.statusCode();
        long probeLen = probe.toByteArray().length();
        long baseLen = baseline.toByteArray().length();
        long delta = probeLen - baseLen;

        // Use SessionVerifier heuristics
        SessionVerifier.VerificationVerdict verdict = SessionVerifier.verify(baseline, probe);

        boolean isSession = false;
        String verdictTitle;
        String details;

        if (verdict.isExpired()) {
            isSession = true;
            verdictTitle = "🚨 Session Token (Required)";
            details = "Removing invalidated session: " + verdict.getSignal();
        } else if (anonBenchmark != null && Math.abs(probeLen - anonBenchmark.toByteArray().length()) <= 20
                && Math.abs(baseLen - anonBenchmark.toByteArray().length()) > 50) {
            // Response closely matches anonymous control response structure
            isSession = true;
            verdictTitle = "🚨 Session Token (Required)";
            details = "Response matches unauthenticated benchmark (" + probeLen + " bytes vs anon "
                    + anonBenchmark.toByteArray().length() + " bytes)";
        } else if (probeStatus != baseStatus) {
            isSession = (probeStatus == 401 || probeStatus == 403 || probeStatus >= 300 && probeStatus < 400);
            verdictTitle = isSession ? "🚨 Session Token (Required)" : "⚠️ Suspicious / Changed";
            details = "Status changed from baseline " + baseStatus + " to " + probeStatus;
        } else if (Math.abs(delta) > 500 && baseLen > 1000) {
            verdictTitle = "⚠️ Significant Content Delta";
            details = "Response body shifted by " + (delta > 0 ? "+" : "") + delta + " bytes";
        } else {
            verdictTitle = "ℹ️ Optional (Non-Session)";
            details = "Session intact; response matches baseline (" + probeStatus + " OK, delta " + (delta >= 0 ? "+" : "") + delta + "B)";
        }

        return new FinderResult(
                id, componentName, type, valuePreview,
                probeStatus, probeLen, delta,
                verdictTitle, details, durationMs,
                probeRR, isSession
        );
    }

    public static Map<String, String> parseCookies(HttpRequest request) {
        Map<String, String> cookies = new LinkedHashMap<>();
        if (request == null) return cookies;

        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase("Cookie")) {
                String val = header.value();
                if (val != null && !val.trim().isEmpty()) {
                    String[] parts = val.split(";");
                    for (String part : parts) {
                        int eq = part.indexOf('=');
                        if (eq > 0) {
                            String name = part.substring(0, eq).trim();
                            String value = part.substring(eq + 1).trim();
                            if (!name.isEmpty()) {
                                cookies.put(name, value);
                            }
                        }
                    }
                }
            }
        }
        return cookies;
    }

    public static Set<String> parseCustomHeaderNames(String input) {
        Set<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        if (input == null || input.trim().isEmpty()) return set;

        String[] tokens = input.split("[,;\\n\\r]+");
        for (String t : tokens) {
            String trimmed = t.trim();
            if (!trimmed.isEmpty()) {
                set.add(trimmed);
            }
        }
        return set;
    }

    public static HttpRequest removeSingleCookie(HttpRequest request, String targetCookie, Map<String, String> allCookies) {
        HttpRequest req = removeAllCookieHeaders(request);
        Map<String, String> remaining = new LinkedHashMap<>(allCookies);
        remaining.remove(targetCookie);

        if (!remaining.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Map.Entry<String, String> e : remaining.entrySet()) {
                if (!first) {
                    sb.append("; ");
                }
                sb.append(e.getKey()).append("=").append(e.getValue());
                first = false;
            }
            req = req.withAddedHeader("Cookie", sb.toString());
        }
        return req;
    }

    public static HttpRequest removeAllCookieHeaders(HttpRequest request) {
        HttpRequest req = request;
        for (HttpHeader h : request.headers()) {
            if (h.name().equalsIgnoreCase("Cookie")) {
                req = req.withRemovedHeader(h);
            }
        }
        return req;
    }

    public static HttpRequest removeHeader(HttpRequest request, String headerName) {
        HttpRequest req = request;
        for (HttpHeader h : request.headers()) {
            if (h.name().equalsIgnoreCase(headerName)) {
                req = req.withRemovedHeader(h);
            }
        }
        return req;
    }

    public static HttpRequest stripAllAuthAndCookies(HttpRequest request, Set<String> customHeaders) {
        HttpRequest req = removeAllCookieHeaders(request);
        for (HttpHeader h : request.headers()) {
            String name = h.name();
            if (STANDARD_AUTH_HEADERS.contains(name) || (customHeaders != null && customHeaders.contains(name))) {
                req = req.withRemovedHeader(h);
            }
        }
        return req;
    }

    private static String previewValue(String value) {
        if (value == null) return "";
        String trimmed = value.trim();
        if (trimmed.length() <= 28) {
            return trimmed;
        }
        return trimmed.substring(0, 25) + "...";
    }

    private void notifyStarted(ExecutionListener listener, int count) {
        if (listener != null) {
            SwingUtilities.invokeLater(() -> listener.onTestStarted(count));
        }
    }

    private void notifyResult(ExecutionListener listener, FinderResult result) {
        if (listener != null) {
            SwingUtilities.invokeLater(() -> listener.onResultAvailable(result));
        }
    }

    private void notifyFinished(ExecutionListener listener, List<FinderResult> results, Set<String> sessionTokens) {
        if (listener != null) {
            SwingUtilities.invokeLater(() -> listener.onFinished(results, sessionTokens));
        }
    }

    private void notifyError(ExecutionListener listener, String error) {
        if (listener != null) {
            SwingUtilities.invokeLater(() -> listener.onError(error));
        }
    }

    public void shutdown() {
        try {
            executor.shutdownNow();
        } catch (Exception ignored) {
        }
    }
}
