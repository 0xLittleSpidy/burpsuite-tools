// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.gwtmap.model.GWTDataStore;
import com.littlespidy.gwtmap.model.GWTMethod;
import com.littlespidy.gwtmap.model.GWTModuleInfo;
import com.littlespidy.gwtmap.model.GWTService;
import com.littlespidy.gwtmap.model.GwtHttpHistoryEntry;
import com.littlespidy.gwtmap.parser.GWTClassifier;
import com.littlespidy.gwtmap.parser.GWTCodeCleaner;
import com.littlespidy.gwtmap.parser.GWTParser;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Asynchronous orchestrator executing GWT file downloads, permutation resolution,
 * deferred fragment stitching, parsing, and live RPC probe testing.
 *
 * @author littlespidy
 */
public class GWTScanEngine {

    private final MontoyaApi api;
    private final GWTDataStore dataStore;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final AtomicInteger historyCounter = new AtomicInteger(1);
    private Consumer<GwtHttpHistoryEntry> httpHistoryListener;

    public GWTScanEngine(MontoyaApi api, GWTDataStore dataStore) {
        this.api = api;
        this.dataStore = dataStore;
    }

    public void setHttpHistoryListener(Consumer<GwtHttpHistoryEntry> listener) {
        this.httpHistoryListener = listener;
    }

    public void resetHistoryCounter() {
        historyCounter.set(1);
    }

    private void recordHistory(String type, String method, String url, int statusCode, int length, long dur, HttpRequestResponse rr) {
        GwtHttpHistoryEntry entry = new GwtHttpHistoryEntry(
                historyCounter.getAndIncrement(),
                type, method, url, statusCode, length, dur, rr
        );
        dataStore.addHttpHistoryEntry(entry);
        if (httpHistoryListener != null) {
            httpHistoryListener.accept(entry);
        }
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    // ── Target Analysis ──────────────────────────────────────────────────────

    public void analyzeUrl(String targetUrl, String baseOverride,
                           Consumer<String> statusListener, Runnable onCompletion) {
        executor.submit(() -> {
            try {
                String fetchUrl = targetUrl;
                if ((fetchUrl == null || fetchUrl.isBlank()) && (baseOverride != null && !baseOverride.isBlank())) {
                    fetchUrl = baseOverride.trim();
                }

                if (fetchUrl == null || fetchUrl.isBlank()) {
                    statusListener.accept("Error: Target URL cannot be empty");
                    if (onCompletion != null) onCompletion.run();
                    return;
                }

                statusListener.accept("Fetching target: " + fetchUrl);
                GWTModuleInfo moduleInfo = new GWTModuleInfo();
                moduleInfo.setTargetUrl(fetchUrl);

                // Compute base directory and extract any permutation hash from baseOverride
                String baseUrl;
                String forcedPermutation = null;

                if (baseOverride != null && !baseOverride.isBlank()) {
                    String trimmed = baseOverride.trim();
                    int lastSlash = trimmed.lastIndexOf('/');
                    if (lastSlash != -1) {
                        String filename = trimmed.substring(lastSlash + 1);
                        if (filename.endsWith(".js") || filename.endsWith(".html")) {
                            baseUrl = trimmed.substring(0, lastSlash + 1);
                            forcedPermutation = filename.replaceAll("\\.(cache|nocache)\\.(js|html)$", "");
                        } else {
                            baseUrl = trimmed.endsWith("/") ? trimmed : trimmed + "/";
                        }
                    } else {
                        baseUrl = trimmed.endsWith("/") ? trimmed : trimmed + "/";
                    }
                } else {
                    int lastSlash = fetchUrl.lastIndexOf('/');
                    baseUrl = (lastSlash != -1) ? fetchUrl.substring(0, lastSlash + 1) : fetchUrl + "/";
                }
                moduleInfo.setBaseUrl(baseUrl);

                long start = System.currentTimeMillis();
                HttpRequest req = HttpRequest.httpRequestFromUrl(fetchUrl);
                HttpRequestResponse rr = api.http().sendRequest(req);
                long dur = System.currentTimeMillis() - start;
                HttpResponse resp = rr.response();

                int code = resp != null ? resp.statusCode() : 0;
                int len = resp != null ? resp.body().length() : 0;
                String type = (fetchUrl.contains(".cache.js") || fetchUrl.contains(".cache.html")) ? "Permutation" : "Bootstrap";
                recordHistory(type, "GET", fetchUrl, code, len, dur, rr);

                if (resp == null || resp.statusCode() != 200) {
                    statusListener.accept("Error: Target returned HTTP " + code + " (expected 200)");
                    if (onCompletion != null) onCompletion.run();
                    return;
                }

                String body = resp.bodyToString();
                processDownloadedCode(body, fetchUrl, baseUrl, forcedPermutation, statusListener, onCompletion);

            } catch (Exception e) {
                statusListener.accept("Analysis failed: " + e.getMessage());
                if (onCompletion != null) onCompletion.run();
            }
        });
    }

    public void analyzeFile(File file, String baseOverride,
                            Consumer<String> statusListener, Runnable onCompletion) {
        executor.submit(() -> {
            try {
                statusListener.accept("Reading local file: " + file.getName());
                String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);

                String baseUrl;
                String forcedPerm = null;
                if (baseOverride != null && !baseOverride.isBlank()) {
                    String trimmed = baseOverride.trim();
                    int lastSlash = trimmed.lastIndexOf('/');
                    if (lastSlash != -1) {
                        String filename = trimmed.substring(lastSlash + 1);
                        if (filename.endsWith(".js") || filename.endsWith(".html")) {
                            baseUrl = trimmed.substring(0, lastSlash + 1);
                            forcedPerm = filename.replaceAll("\\.(cache|nocache)\\.(js|html)$", "");
                        } else {
                            baseUrl = trimmed.endsWith("/") ? trimmed : trimmed + "/";
                        }
                    } else {
                        baseUrl = trimmed.endsWith("/") ? trimmed : trimmed + "/";
                    }
                } else {
                    baseUrl = "http://127.0.0.1/stub/";
                }

                processDownloadedCode(content, file.getAbsolutePath(), baseUrl, forcedPerm, statusListener, onCompletion);

            } catch (Exception e) {
                statusListener.accept("Failed reading file: " + e.getMessage());
                if (onCompletion != null) onCompletion.run();
            }
        });
    }

    private void processDownloadedCode(String rawContent, String sourcePath, String baseUrl,
                                      String forcedPermutation,
                                      Consumer<String> statusListener, Runnable onCompletion) {
        try {
            if (forcedPermutation == null && sourcePath != null && sourcePath.contains(".cache.")) {
                int slash = Math.max(sourcePath.lastIndexOf('/'), sourcePath.lastIndexOf(File.separatorChar));
                String fname = slash != -1 ? sourcePath.substring(slash + 1) : sourcePath;
                String hash = fname.replaceAll("\\.(cache|nocache)\\.(js|html)$", "");
                if (!hash.isBlank() && !hash.equals(fname)) {
                    forcedPermutation = hash;
                }
            }

            dataStore.setRawCode(rawContent);
            GWTClassifier.CodeType codeType = GWTClassifier.classify(rawContent);
            statusListener.accept("Classified resource as: " + codeType.name());

            GWTModuleInfo info = new GWTModuleInfo();
            info.setTargetUrl(sourcePath);
            info.setBaseUrl(baseUrl);

            List<String> cleanedLines = GWTCodeCleaner.cleanCode(rawContent, codeType);

            // Handle bootstrap file -> resolve permutations
            if (codeType == GWTClassifier.CodeType.BOOTSTRAP_OBFUSCATED
                    || codeType == GWTClassifier.CodeType.BOOTSTRAP_CLEAN) {
                statusListener.accept("Extracting permutations from bootstrap file...");
                List<String> permutations = GWTParser.extractPermutations(cleanedLines, codeType);

                if (forcedPermutation != null && !forcedPermutation.isBlank() && !permutations.contains(forcedPermutation)) {
                    permutations.add(0, forcedPermutation);
                }
                info.setAllPermutations(permutations);

                if (!permutations.isEmpty()) {
                    String selectedPerm = (forcedPermutation != null && !forcedPermutation.isBlank())
                            ? forcedPermutation
                            : permutations.get(0);
                    info.setActivePermutation(selectedPerm);
                    statusListener.accept("Selected permutation " + selectedPerm + " (" + permutations.size() + " total discovered)");

                    // If online URL, download the permutation file
                    if (sourcePath.startsWith("http://") || sourcePath.startsWith("https://")) {
                        String permUrl = baseUrl + selectedPerm + ".cache.js";
                        statusListener.accept("Fetching permutation cache: " + permUrl);
                        try {
                            long pStart = System.currentTimeMillis();
                            HttpRequest pReq = HttpRequest.httpRequestFromUrl(permUrl);
                            HttpRequestResponse pRr = api.http().sendRequest(pReq);
                            long pDur = System.currentTimeMillis() - pStart;
                            int pCode = pRr.response() != null ? pRr.response().statusCode() : 0;
                            int pLen = pRr.response() != null ? pRr.response().body().length() : 0;
                            recordHistory("Permutation", "GET", permUrl, pCode, pLen, pDur, pRr);

                            if (pRr.response() != null && pRr.response().statusCode() == 200) {
                                rawContent = pRr.response().bodyToString();
                                dataStore.setRawCode(rawContent);
                                codeType = GWTClassifier.classify(rawContent);
                                cleanedLines = GWTCodeCleaner.cleanCode(rawContent, codeType);
                            }
                        } catch (Exception pe) {
                            statusListener.accept("Warning: Could not fetch permutation: " + pe.getMessage());
                        }
                    }
                } else {
                    statusListener.accept("Warning: No permutation hashes found in bootstrap.");
                }
            }

            // Extract module metadata
            GWTParser.extractModuleInfo(cleanedLines, info);
            if (forcedPermutation != null && !forcedPermutation.isBlank()) {
                if ("Unknown".equals(info.getActivePermutation())) {
                    info.setActivePermutation(forcedPermutation);
                }
                if (info.getAllPermutations().isEmpty()) {
                    List<String> perms = new ArrayList<>();
                    perms.add(forcedPermutation);
                    info.setAllPermutations(perms);
                }
            }
            statusListener.accept("GWT Version: " + info.getGwtVersion() + " | RPC: v" + info.getRpcVersion());

            // Check for deferred fragments
            if (sourcePath.startsWith("http://") || sourcePath.startsWith("https://")) {
                if (GWTParser.isFragmented(rawContent)) {
                    statusListener.accept("Permutation is fragmented. Enumerating deferred fragments...");
                    appendDeferredFragments(cleanedLines, info, statusListener);
                }
            }

            dataStore.setCleanedCode(String.join("\n", cleanedLines));
            dataStore.setModuleInfo(info);

            // Pre-index variable definitions once in a single fast linear pass
            statusListener.accept("Indexing JavaScript variables...");
            Map<String, String> varMap = GWTParser.buildVariableMap(cleanedLines);

            // Extract services using varMap
            statusListener.accept("Enumerating GWT services...");
            List<GWTService> services = GWTParser.extractServiceInfo(cleanedLines, varMap);
            dataStore.setServices(services);
            statusListener.accept("Found " + services.size() + " GWT service endpoints.");

            // Extract methods using varMap
            statusListener.accept("Enumerating RPC methods and building payloads...");
            List<GWTMethod> methods = GWTParser.extractMethodInfo(cleanedLines, services, info, varMap);
            dataStore.setMethods(methods);
            statusListener.accept("Extracted " + methods.size() + " methods across " + services.size() + " services.");

        } catch (Exception e) {
            statusListener.accept("Error during parsing: " + e.getMessage());
        } finally {
            if (onCompletion != null) onCompletion.run();
        }
    }

    private void appendDeferredFragments(List<String> cleanedLines, GWTModuleInfo info,
                                         Consumer<String> statusListener) {
        int misses = 0;
        int frag = 0;
        String perm = info.getActivePermutation();
        if (perm.equals("Unknown")) return;

        while (misses < 2 && frag < 100) {
            String fragUrl = info.getBaseUrl() + "deferredjs/" + perm + "/" + frag + ".cache.js";
            try {
                long fStart = System.currentTimeMillis();
                HttpRequest fReq = HttpRequest.httpRequestFromUrl(fragUrl);
                HttpRequestResponse fRr = api.http().sendRequest(fReq);
                long fDur = System.currentTimeMillis() - fStart;
                int fCode = fRr.response() != null ? fRr.response().statusCode() : 0;
                int fLen = fRr.response() != null ? fRr.response().body().length() : 0;
                recordHistory("Fragment #" + frag, "GET", fragUrl, fCode, fLen, fDur, fRr);

                if (fRr.response() != null && fRr.response().statusCode() == 200) {
                    String fragCode = fRr.response().bodyToString();
                    if (!fragCode.isBlank()) {
                        info.addDeferredFragment(fragUrl);
                        statusListener.accept("  + Appended fragment: " + fragUrl);
                        GWTClassifier.CodeType fType = GWTClassifier.classify(fragCode);
                        cleanedLines.addAll(GWTCodeCleaner.cleanCode(fragCode, fType));
                        misses = 0;
                    } else {
                        misses++;
                    }
                } else {
                    misses++;
                }
            } catch (Exception e) {
                misses++;
            }
            frag++;
        }
    }

    // ── HTTP Probing Engine ──────────────────────────────────────────────────

    public HttpRequest buildHttpRequest(GWTMethod method, String customHeaders, boolean includeIntruderMarkers) {
        GWTModuleInfo info = dataStore.getModuleInfo();
        String url = method.getFullEndpointUrl();
        if (url == null || url.isBlank()) {
            url = info.getBaseUrl();
        }

        HttpRequest req = HttpRequest.httpRequestFromUrl(url);
        req = req.withMethod("POST");
        req = req.withHeader("Content-Type", info.getContentType());
        req = req.withHeader("X-GWT-Permutation", info.getActivePermutation());
        req = req.withHeader("X-GWT-Module-Base", info.getBaseUrl());

        // Apply custom headers / cookies
        if (customHeaders != null && !customHeaders.isBlank()) {
            String[] lines = customHeaders.split("\n");
            for (String line : lines) {
                line = line.trim();
                int colon = line.indexOf(':');
                if (colon > 0 && colon < line.length() - 1) {
                    String name = line.substring(0, colon).trim();
                    String val = line.substring(colon + 1).trim();
                    req = req.withHeader(name, val);
                }
            }
        }

        String body = includeIntruderMarkers ? method.getMethodRpcCall() : method.getRawRpcCall();
        req = req.withBody(body);
        return req;
    }

    public void sendProbe(GWTMethod method, String customHeaders, Consumer<GWTMethod> onComplete) {
        executor.submit(() -> {
            try {
                HttpRequest probeReq = buildHttpRequest(method, customHeaders, false);
                long start = System.currentTimeMillis();
                HttpRequestResponse rr = api.http().sendRequest(probeReq);
                long elapsed = System.currentTimeMillis() - start;

                HttpResponse resp = rr.response();
                int code = resp != null ? resp.statusCode() : 0;
                int len = resp != null ? resp.body().length() : 0;
                recordHistory("Probe: " + method.getMethodName(), "POST", method.getFullEndpointUrl(), code, len, elapsed, rr);
                method.setProbeResult(probeReq, resp, elapsed);
            } catch (Exception e) {
                method.setProbeResult(null, null, 0);
            } finally {
                if (onComplete != null) onComplete.accept(method);
            }
        });
    }

    public void probeAll(List<GWTMethod> methods, String customHeaders,
                         Consumer<Integer> progressListener, Runnable onCompletion) {
        executor.submit(() -> {
            try {
                int total = methods.size();
                int current = 0;
                for (GWTMethod method : methods) {
                    HttpRequest probeReq = buildHttpRequest(method, customHeaders, false);
                    long start = System.currentTimeMillis();
                    try {
                        HttpRequestResponse rr = api.http().sendRequest(probeReq);
                        long elapsed = System.currentTimeMillis() - start;
                        HttpResponse resp = rr.response();
                        int code = resp != null ? resp.statusCode() : 0;
                        int len = resp != null ? resp.body().length() : 0;
                        recordHistory("Probe: " + method.getMethodName(), "POST", method.getFullEndpointUrl(), code, len, elapsed, rr);
                        method.setProbeResult(probeReq, resp, elapsed);
                    } catch (Exception e) {
                        method.setProbeResult(probeReq, null, 0);
                    }
                    current++;
                    if (progressListener != null) progressListener.accept(current);
                }
            } finally {
                if (onCompletion != null) onCompletion.run();
            }
        });
    }
}
