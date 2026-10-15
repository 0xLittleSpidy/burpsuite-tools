// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.gwtmap.model.GWTRpcPayload;
import com.littlespidy.gwtmap.parser.GwtLongCodec;
import com.littlespidy.gwtmap.parser.GWTRpcDeserializer;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Automated GWT-RPC fuzzer and parameter manipulation engine porting gwtfuzzer.
 * Tests string inputs with security payloads and numeric IDs with delta ranges,
 * detecting serialized GWT server-side exceptions (//EX[).
 *
 * @author littlespidy
 */
public class GWTFuzzerEngine {

    public static class FuzzResult {
        private final int id;
        private final String targetUrl;
        private final String method;
        private final String attackType;
        private final String payload;
        private final int statusCode;
        private final int responseLength;
        private final long responseTimeMs;
        private final boolean gwtException;
        private final String errorNotes;
        private final HttpRequest request;
        private final HttpResponse response;

        public FuzzResult(int id, String targetUrl, String method, String attackType, String payload,
                          int statusCode, int responseLength, long responseTimeMs,
                          boolean gwtException, String errorNotes,
                          HttpRequest request, HttpResponse response) {
            this.id = id;
            this.targetUrl = targetUrl != null ? targetUrl : "";
            this.method = method != null ? method : "";
            this.attackType = attackType != null ? attackType : "";
            this.payload = payload != null ? payload : "";
            this.statusCode = statusCode;
            this.responseLength = responseLength;
            this.responseTimeMs = responseTimeMs;
            this.gwtException = gwtException;
            this.errorNotes = errorNotes != null ? errorNotes : "";
            this.request = request;
            this.response = response;
        }

        public int getId() { return id; }
        public String getTargetUrl() { return targetUrl; }
        public String getMethod() { return method; }
        public String getAttackType() { return attackType; }
        public String getPayload() { return payload; }
        public int getStatusCode() { return statusCode; }
        public int getResponseLength() { return responseLength; }
        public long getResponseTimeMs() { return responseTimeMs; }
        public boolean isGwtException() { return gwtException; }
        public String getErrorNotes() { return errorNotes; }
        public HttpRequest getRequest() { return request; }
        public HttpResponse getResponse() { return response; }
    }

    private final MontoyaApi api;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    // Common error signatures from gwtfuzzer
    private static final List<String> COMMON_ERROR_SIGNATURES = List.of(
            "SQL syntax", "ORA-", "PostgreSQL", "NullPointerException",
            "IllegalArgumentException", "HibernateException", "ClassCastException",
            "IndexOutOfBoundsException", "SecurityException"
    );

    public GWTFuzzerEngine(MontoyaApi api) {
        this.api = api;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public void shutdown() {
        cancelled.set(true);
        executor.shutdownNow();
    }

    /**
     * Checks if a response contains a serialized GWT Exception.
     */
    public static boolean isGwtException(String responseBody) {
        if (responseBody == null) return false;
        return responseBody.startsWith("//EX[") || responseBody.contains("//EX[");
    }

    /**
     * Audits response content for error signatures and exception messages.
     */
    public static String auditErrors(int statusCode, String responseBody) {
        List<String> found = new ArrayList<>();
        if (isGwtException(responseBody)) {
            found.add("GWT Exception (//EX[)");
        }
        if (statusCode >= 500) {
            found.add("HTTP " + statusCode + " Server Error");
        }
        if (responseBody != null) {
            for (String sig : COMMON_ERROR_SIGNATURES) {
                if (responseBody.contains(sig)) {
                    found.add(sig);
                }
            }
        }
        return String.join(", ", found);
    }

    /**
     * Runs automated fuzzing across the given baseline GWT request.
     */
    public void startFuzzing(
            HttpRequest baseRequest,
            List<String> stringPayloads,
            int idRange,
            Consumer<FuzzResult> onResult,
            Consumer<Integer> onProgress,
            Runnable onCompletion) {
        startFuzzing(baseRequest, stringPayloads, idRange, onResult,
                (cur, tot) -> { if (onProgress != null) onProgress.accept(cur); }, onCompletion);
    }

    public void startFuzzing(
            HttpRequest baseRequest,
            List<String> stringPayloads,
            int idRange,
            Consumer<FuzzResult> onResult,
            java.util.function.BiConsumer<Integer, Integer> onProgress,
            Runnable onCompletion) {

        cancelled.set(false);
        executor.submit(() -> {
            try {
                String rawBody = baseRequest.bodyToString();
                GWTRpcPayload parsed = GWTRpcDeserializer.deserialize(rawBody);
                String[] baseTokens = rawBody.split("\\|", -1);
                boolean hasTrailing = rawBody.endsWith("|");

                String methodName = parsed.getServiceInterface() + "." + parsed.getMethodName();
                Map<Integer, String> fuzzables = parsed.getFuzzableIndices();

                int totalProbes = 0;
                for (String type : fuzzables.values()) {
                    if ("%s".equals(type) && stringPayloads != null) {
                        totalProbes += stringPayloads.size();
                    } else if ("%d".equals(type) && idRange > 0) {
                        totalProbes += (idRange * 2);
                    }
                }
                final int finalTotal = totalProbes;
                if (onProgress != null) onProgress.accept(0, finalTotal);

                int currentCount = 0;
                int resultId = 1;

                for (Map.Entry<Integer, String> entry : fuzzables.entrySet()) {
                    if (cancelled.get()) break;

                    int tokenIdx = entry.getKey();
                    String fuzzType = entry.getValue();

                    if ("%s".equals(fuzzType) && stringPayloads != null) {
                        for (String payload : stringPayloads) {
                            if (cancelled.get()) break;

                            String escapedPayload = payload.replace("|", "\\!");
                            String[] mutatedTokens = Arrays.copyOf(baseTokens, baseTokens.length);
                            mutatedTokens[tokenIdx] = escapedPayload;

                            StringBuilder mutatedBody = new StringBuilder();
                            for (int i = 0; i < mutatedTokens.length; i++) {
                                mutatedBody.append(mutatedTokens[i]);
                                if (i < mutatedTokens.length - 1 || hasTrailing) {
                                    mutatedBody.append("|");
                                }
                            }

                            HttpRequest probeReq = baseRequest.withBody(mutatedBody.toString());
                            long start = System.currentTimeMillis();
                            try {
                                HttpRequestResponse rr = api.http().sendRequest(probeReq);
                                long elapsed = System.currentTimeMillis() - start;
                                HttpResponse resp = rr.response();

                                int code = resp != null ? resp.statusCode() : 0;
                                int length = resp != null ? resp.body().length() : 0;
                                String bodyText = resp != null ? resp.bodyToString() : "";
                                boolean isEx = isGwtException(bodyText);
                                String errors = auditErrors(code, bodyText);

                                FuzzResult result = new FuzzResult(
                                        resultId++, baseRequest.url(), methodName,
                                        "String Injection", payload, code, length, elapsed,
                                        isEx, errors, probeReq, resp
                                );
                                if (onResult != null) onResult.accept(result);

                            } catch (Exception e) {
                                FuzzResult failResult = new FuzzResult(
                                        resultId++, baseRequest.url(), methodName,
                                        "String Injection", payload, 0, 0, 0,
                                        false, "Connection Failed", probeReq, null
                                );
                                if (onResult != null) onResult.accept(failResult);
                            }

                            currentCount++;
                            if (onProgress != null) onProgress.accept(currentCount, finalTotal);
                        }
                    } else if ("%d".equals(fuzzType) && idRange > 0) {
                        String origValStr = (tokenIdx < baseTokens.length) ? baseTokens[tokenIdx] : "0";
                        long origNum = 0;
                        try {
                            origNum = Long.parseLong(origValStr);
                        } catch (NumberFormatException e) {
                            origNum = GwtLongCodec.decode(origValStr);
                        }

                        long startNum = Math.max(0, origNum - idRange);
                        long endNum = origNum + idRange;

                        for (long i = startNum; i <= endNum; i++) {
                            if (i == origNum) continue;
                            if (cancelled.get()) break;

                            String mutatedVal = String.valueOf(i);
                            String[] mutatedTokens = Arrays.copyOf(baseTokens, baseTokens.length);
                            mutatedTokens[tokenIdx] = mutatedVal;

                            StringBuilder mutatedBody = new StringBuilder();
                            for (int k = 0; k < mutatedTokens.length; k++) {
                                mutatedBody.append(mutatedTokens[k]);
                                if (k < mutatedTokens.length - 1 || hasTrailing) {
                                    mutatedBody.append("|");
                                }
                            }

                            HttpRequest probeReq = baseRequest.withBody(mutatedBody.toString());
                            long start = System.currentTimeMillis();
                            try {
                                HttpRequestResponse rr = api.http().sendRequest(probeReq);
                                long elapsed = System.currentTimeMillis() - start;
                                HttpResponse resp = rr.response();

                                int code = resp != null ? resp.statusCode() : 0;
                                int length = resp != null ? resp.body().length() : 0;
                                String bodyText = resp != null ? resp.bodyToString() : "";
                                boolean isEx = isGwtException(bodyText);
                                String errors = auditErrors(code, bodyText);

                                FuzzResult result = new FuzzResult(
                                        resultId++, baseRequest.url(), methodName,
                                        "ID Manipulation", mutatedVal, code, length, elapsed,
                                        isEx, errors, probeReq, resp
                                );
                                if (onResult != null) onResult.accept(result);

                            } catch (Exception e) {
                                FuzzResult failResult = new FuzzResult(
                                        resultId++, baseRequest.url(), methodName,
                                        "ID Manipulation", mutatedVal, 0, 0, 0,
                                        false, "Connection Failed", probeReq, null
                                );
                                if (onResult != null) onResult.accept(failResult);
                            }

                            currentCount++;
                            if (onProgress != null) onProgress.accept(currentCount, finalTotal);
                        }
                    }
                }

            } finally {
                if (onCompletion != null) onCompletion.run();
            }
        });
    }
}
