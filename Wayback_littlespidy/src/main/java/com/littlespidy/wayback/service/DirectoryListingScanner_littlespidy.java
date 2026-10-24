// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.wayback.config.CommonConfig_littlespidy;
import com.littlespidy.wayback.model.DirectoryFinding_littlespidy;
import com.littlespidy.wayback.model.DiscoveredPath_littlespidy;
import com.littlespidy.wayback.model.DomainScanConfig_littlespidy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class DirectoryListingScanner_littlespidy {

    private final MontoyaApi api;
    private final CommonConfig_littlespidy commonConfig;
    private final DomainScanConfig_littlespidy scanConfig;

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicBoolean isPaused = new AtomicBoolean(false);
    private final Object pauseLock = new Object();

    private ExecutorService threadPool;
    private final AtomicInteger findingIdCounter = new AtomicInteger(1);

    public interface ScanProgressCallback {
        void onProgress(int completed, int total, String currentPath);
        void onFindingDiscovered(DirectoryFinding_littlespidy finding);
        void onPathUpdated(DiscoveredPath_littlespidy path);
        void onScanCompleted();
    }

    public DirectoryListingScanner_littlespidy(
            MontoyaApi api,
            CommonConfig_littlespidy commonConfig,
            DomainScanConfig_littlespidy scanConfig) {
        this.api = api;
        this.commonConfig = commonConfig != null ? commonConfig : new CommonConfig_littlespidy();
        this.scanConfig = scanConfig != null ? scanConfig : new DomainScanConfig_littlespidy();
    }

    public void startScan(List<DiscoveredPath_littlespidy> paths, ScanProgressCallback callback) {
        if (paths == null || paths.isEmpty()) {
            if (callback != null) callback.onScanCompleted();
            return;
        }

        stopScan();

        isRunning.set(true);
        isPaused.set(false);

        int threads = Math.max(1, scanConfig.getThreads());
        threadPool = Executors.newFixedThreadPool(threads, new ThreadFactory() {
            private final AtomicInteger count = new AtomicInteger(1);
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "Wayback-Scanner-Thread-" + count.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        });

        int total = paths.size();
        AtomicInteger completedCount = new AtomicInteger(0);

        for (DiscoveredPath_littlespidy pathItem : paths) {
            threadPool.submit(() -> {
                if (!isRunning.get()) return;

                checkPauseState();
                if (!isRunning.get()) return;

                pathItem.setStatus("Probing");
                if (callback != null) {
                    callback.onPathUpdated(pathItem);
                    callback.onProgress(completedCount.get(), total, pathItem.getPath());
                }

                probePath(pathItem, callback);

                int done = completedCount.incrementAndGet();
                if (callback != null) {
                    callback.onPathUpdated(pathItem);
                    callback.onProgress(done, total, pathItem.getPath());
                    if (done >= total) {
                        isRunning.set(false);
                        callback.onScanCompleted();
                    }
                }

                int delay = scanConfig.getDelayMs();
                if (delay > 0) {
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            });
        }
    }

    private void probePath(DiscoveredPath_littlespidy pathItem, ScanProgressCallback callback) {
        String host = pathItem.getHost();
        String rawPath = pathItem.getPath();
        if (!rawPath.startsWith("/")) {
            rawPath = "/" + rawPath;
        }
        // Normalize directory check by appending trailing slash if not file extension
        String testPath = rawPath.endsWith("/") ? rawPath : rawPath + "/";

        List<String> protocols = new ArrayList<>();
        if (commonConfig.isTestBothHttpHttps()) {
            protocols.add("https");
            protocols.add("http");
        } else {
            protocols.add("https");
        }

        String userAgent = commonConfig.getUserAgent();
        int timeoutSec = scanConfig.getTimeoutSec();

        for (String protocol : protocols) {
            if (!isRunning.get()) return;
            checkPauseState();

            try {
                ProbeResult probe = executeProbe(protocol, host, testPath, userAgent, timeoutSec);
                if (probe != null) {
                    pathItem.setLastTestedProtocol(protocol.toUpperCase());
                    pathItem.setStatusCode(probe.statusCode);
                    pathItem.setContentLength(probe.contentLength);

                    if (probe.statusCode == 200) {
                        String matchedSig = commonConfig.findMatchingSignature(probe.responseBody);
                        if (matchedSig != null) {
                            pathItem.setResult("Open Listing");
                            pathItem.setStatus("Checked");

                            DirectoryFinding_littlespidy finding = new DirectoryFinding_littlespidy(
                                    findingIdCounter.getAndIncrement(),
                                    protocol.toUpperCase(),
                                    host,
                                    testPath,
                                    protocol + "://" + host + testPath,
                                    probe.statusCode,
                                    matchedSig,
                                    probe.contentLength,
                                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                                    probe.burpRequest,
                                    probe.burpResponse
                            );

                            if (probe.rawRequest != null) {
                                finding.setRawRequestBase64(java.util.Base64.getEncoder().encodeToString(probe.rawRequest.getBytes()));
                            }
                            if (probe.rawResponse != null) {
                                finding.setRawResponseBase64(java.util.Base64.getEncoder().encodeToString(probe.rawResponse.getBytes()));
                            }

                            if (callback != null) {
                                callback.onFindingDiscovered(finding);
                            }

                            if (api != null && scanConfig.isAddToSiteMap() && probe.httpRequestResponse != null) {
                                try {
                                    api.siteMap().add(probe.httpRequestResponse);
                                } catch (Exception ignored) {
                                }
                            }
                            return;
                        } else {
                            pathItem.setResult("Normal Page");
                            pathItem.setStatus("Checked");
                        }
                    } else if (probe.statusCode == 403) {
                        pathItem.setResult("403 Forbidden");
                        pathItem.setStatus("Checked");
                    } else if (probe.statusCode == 404) {
                        pathItem.setResult("Not Found");
                        pathItem.setStatus("Checked");
                    } else {
                        pathItem.setResult("HTTP " + probe.statusCode);
                        pathItem.setStatus("Checked");
                    }
                }
            } catch (Exception ex) {
                pathItem.setStatus("Failed");
                pathItem.setResult("Error");
            }
        }
    }

    private ProbeResult executeProbe(String protocol, String host, String path, String userAgent, int timeoutSec) throws Exception {
        boolean isSecure = protocol.equalsIgnoreCase("https");
        int port = isSecure ? 443 : 80;

        if (api != null) {
            HttpService service = HttpService.httpService(host, port, isSecure);
            HttpRequest req = HttpRequest.httpRequest(service,
                    "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "User-Agent: " + userAgent + "\r\n" +
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
                    "Accept-Language: en-US,en;q=0.5\r\n" +
                    "Connection: close\r\n\r\n");

            HttpRequestResponse reqResp = api.http().sendRequest(req);
            if (reqResp != null && reqResp.response() != null) {
                HttpResponse resp = reqResp.response();
                ProbeResult result = new ProbeResult();
                result.statusCode = resp.statusCode();
                result.responseBody = resp.bodyToString();
                result.contentLength = resp.body().length();
                result.burpRequest = req;
                result.burpResponse = resp;
                result.httpRequestResponse = reqResp;
                result.rawRequest = req.toString();
                result.rawResponse = resp.toString();
                return result;
            }
        }

        // Standalone fallback
        String urlString = protocol + "://" + host + (port == 80 || port == 443 ? "" : ":" + port) + path;
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(timeoutSec))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(urlString))
                .header("User-Agent", userAgent)
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .timeout(Duration.ofSeconds(timeoutSec))
                .GET()
                .build();

        java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString());
        ProbeResult result = new ProbeResult();
        result.statusCode = resp.statusCode();
        result.responseBody = resp.body();
        result.contentLength = resp.body() != null ? resp.body().getBytes().length : 0;
        result.rawRequest = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + userAgent + "\r\n\r\n";
        result.rawResponse = "HTTP/1.1 " + resp.statusCode() + " OK\r\n\r\n" + (resp.body() != null ? resp.body() : "");
        return result;
    }

    private void checkPauseState() {
        synchronized (pauseLock) {
            while (isPaused.get() && isRunning.get()) {
                try {
                    pauseLock.wait(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    public void pauseScan() {
        isPaused.set(true);
    }

    public void resumeScan() {
        synchronized (pauseLock) {
            isPaused.set(false);
            pauseLock.notifyAll();
        }
    }

    public void stopScan() {
        isRunning.set(false);
        resumeScan();
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdownNow();
        }
    }

    public boolean isRunning() {
        return isRunning.get();
    }

    public boolean isPaused() {
        return isPaused.get();
    }

    private static class ProbeResult {
        int statusCode;
        String responseBody;
        int contentLength;
        HttpRequest burpRequest;
        HttpResponse burpResponse;
        HttpRequestResponse httpRequestResponse;
        String rawRequest;
        String rawResponse;
    }
}
