package com.littlespidy.uploadscanner.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.uploadscanner.model.PayloadDefinition;
import com.littlespidy.uploadscanner.model.StageType;
import com.littlespidy.uploadscanner.model.UploadEntry;
import com.littlespidy.uploadscanner.model.UploadScannerConfig;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe execution engine that manages upload tests, preflight/redownload chains,
 * visual marker extraction, and streaming of results to the log.
 *
 * @author littlespidy
 */
public class UploadScanExecutor {
    private final MontoyaApi api;
    private final UploadScannerConfig config;
    private final Consumer<UploadEntry> entryConsumer;
    private final Consumer<String> statusConsumer;
    private final Runnable completionCallback;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final AtomicInteger sequenceCounter = new AtomicInteger(1);
    private SwingWorker<Void, UploadEntry> worker;

    public UploadScanExecutor(MontoyaApi api,
                              UploadScannerConfig config,
                              Consumer<UploadEntry> entryConsumer,
                              Consumer<String> statusConsumer,
                              Runnable completionCallback) {
        this.api = api;
        this.config = config;
        this.entryConsumer = entryConsumer;
        this.statusConsumer = statusConsumer;
        this.completionCallback = completionCallback;
    }

    public boolean isRunning() {
        return running.get();
    }

    public void stop() {
        running.set(false);
        if (worker != null && !worker.isDone()) {
            worker.cancel(true);
        }
    }

    public void startScan(HttpRequest baseRequest) {
        if (running.get()) {
            return;
        }

        running.set(true);
        paused.set(false);
        statusConsumer.accept("Starting scan...");

        worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    executeScan(baseRequest);
                } catch (Exception e) {
                    api.logging().logToError("Error during upload scan: " + e.getMessage());
                }
                return null;
            }

            @Override
            protected void done() {
                running.set(false);
                statusConsumer.accept("Scan finished.");
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        };

        worker.execute();
    }

    private void executeScan(HttpRequest baseRequest) {
        ReDownloaderEngine redlEngine = new ReDownloaderEngine(api, config.getRedownloaderConfig());
        String originalFilename = extractFilenameFromRequest(baseRequest);
        List<PayloadDefinition> payloads = UploadPayloadGenerator.generatePayloads(config, originalFilename);

        int total = payloads.size();
        for (int i = 0; i < total; i++) {
            if (!running.get()) {
                break;
            }

            PayloadDefinition payload = payloads.get(i);
            int currentStep = i + 1;
            statusConsumer.accept(String.format("Testing [%d/%d]: %s", currentStep, total, payload.getName()));

            // ── Step 1: Preflight Request (if configured) ──
            HttpRequestResponse preflightPair = null;
            if (config.getRedownloaderConfig().isEnabled() &&
                    !config.getRedownloaderConfig().getPreflightUrl().isEmpty()) {
                preflightPair = redlEngine.executePreflight(baseRequest);
                if (preflightPair != null) {
                    int preId = sequenceCounter.getAndIncrement();
                    short preStatus = preflightPair.hasResponse() ? preflightPair.response().statusCode() : 0;
                    int preLen = preflightPair.hasResponse() ? preflightPair.response().body().length() : 0;

                    UploadEntry preflightEntry = new UploadEntry(
                            preId,
                            StageType.PREFLIGHT,
                            preflightPair.request().method(),
                            preStatus,
                            "Preflight: " + payload.getFilename(),
                            preLen,
                            preflightPair.request().url(),
                            preflightPair,
                            "",
                            null,
                            null
                    );
                    publishEntry(preflightEntry);
                }
            }

            // ── Step 2: Build & Send Upload Request ──
            HttpRequest uploadReq = injectPayload(baseRequest, payload);
            HttpRequestResponse uploadPair = api.http().sendRequest(uploadReq);

            if (uploadPair == null) {
                continue;
            }

            short uploadStatus = uploadPair.hasResponse() ? uploadPair.response().statusCode() : 0;
            int uploadLen = uploadPair.hasResponse() ? uploadPair.response().body().length() : 0;
            String uploadResponseStr = uploadPair.hasResponse() ? uploadPair.response().bodyToString() : "";

            // Check if ReDownloader can parse a URL from upload response or preflight response
            MarkerHighlighter.ExtractionResult extraction =
                    redlEngine.parseDownloadUrl(uploadResponseStr, payload.getFilename());

            if (!extraction.isFound() && preflightPair != null && preflightPair.hasResponse()) {
                extraction = redlEngine.parseDownloadUrl(preflightPair.response().bodyToString(), payload.getFilename());
            }

            List<Marker> uploadMarkers = new ArrayList<>();
            String extractedUrl = "";
            if (extraction.isFound()) {
                extractedUrl = extraction.getExtractedText();
                uploadMarkers.addAll(extraction.toMarkers());
                if (!uploadMarkers.isEmpty()) {
                    uploadPair = uploadPair.withResponseMarkers(uploadMarkers);
                }
            }

            int uploadId = sequenceCounter.getAndIncrement();
            UploadEntry uploadEntry = new UploadEntry(
                    uploadId,
                    StageType.UPLOAD,
                    uploadReq.method(),
                    uploadStatus,
                    payload.getName() + " (" + payload.getFilename() + ")",
                    uploadLen,
                    uploadReq.url(),
                    uploadPair,
                    extractedUrl,
                    uploadMarkers,
                    null
            );
            publishEntry(uploadEntry);

            // ── Step 3: ReDownloader Request (if URL was extracted or static URL is active) ──
            if (config.getRedownloaderConfig().isEnabled() && extraction.isFound()) {
                HttpRequest redlReq = redlEngine.buildRedownloadRequest(baseRequest, extraction.getExtractedText());
                if (redlReq != null) {
                    HttpRequestResponse redlPair = redlEngine.executeRedownload(redlReq, payload.getExecutionMarker());
                    if (redlPair != null) {
                        int redlId = sequenceCounter.getAndIncrement();
                        short redlStatus = redlPair.hasResponse() ? redlPair.response().statusCode() : 0;
                        int redlLen = redlPair.hasResponse() ? redlPair.response().body().length() : 0;

                        List<Marker> redlMarkers = new ArrayList<>();
                        if (redlPair.hasResponse() && !payload.getExecutionMarker().isEmpty()) {
                            redlMarkers.addAll(MarkerHighlighter.findMarkers(
                                    redlPair.response().bodyToString(), payload.getExecutionMarker()));
                        }

                        UploadEntry redlEntry = new UploadEntry(
                                redlId,
                                StageType.REDOWNLOAD,
                                redlReq.method(),
                                redlStatus,
                                "ReDownload: " + payload.getFilename(),
                                redlLen,
                                redlReq.url(),
                                redlPair,
                                payload.getExecutionMarker().isEmpty() ? extractedUrl : payload.getExecutionMarker(),
                                redlMarkers,
                                null
                        );
                        publishEntry(redlEntry);
                    }
                }
            }

            // ── Throttling ──
            if (config.getThrottleMs() > 0) {
                try {
                    Thread.sleep(config.getThrottleMs());
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private void publishEntry(UploadEntry entry) {
        SwingUtilities.invokeLater(() -> entryConsumer.accept(entry));
    }

    private String extractFilenameFromRequest(HttpRequest request) {
        String body = request.bodyToString();
        int idx = body.indexOf("filename=\"");
        if (idx != -1) {
            int end = body.indexOf("\"", idx + 10);
            if (end != -1) {
                return body.substring(idx + 10, end);
            }
        }
        return "upload.jpg";
    }

    private HttpRequest injectPayload(HttpRequest baseRequest, PayloadDefinition payload) {
        String body = baseRequest.bodyToString();
        int fnIdx = body.indexOf("filename=\"");

        if (fnIdx != -1) {
            int fnEnd = body.indexOf("\"", fnIdx + 10);
            if (fnEnd != -1) {
                // Replace filename
                String newBody = body.substring(0, fnIdx + 10) + payload.getFilename() + body.substring(fnEnd);

                // Look for Content-Type within multipart part
                int ctIdx = newBody.indexOf("Content-Type: ", fnIdx);
                if (ctIdx != -1 && ctIdx < fnIdx + 200) {
                    int ctEnd = newBody.indexOf("\r\n", ctIdx);
                    if (ctEnd != -1) {
                        newBody = newBody.substring(0, ctIdx + 14) + payload.getContentType() + newBody.substring(ctEnd);
                    }
                }

                // Replace file content between header double-newline and next boundary
                int headerEnd = newBody.indexOf("\r\n\r\n", fnIdx);
                if (headerEnd != -1) {
                    int contentStart = headerEnd + 4;
                    int boundaryIdx = newBody.indexOf("\r\n--", contentStart);
                    if (boundaryIdx != -1) {
                        String payloadContentStr = new String(payload.getContent(), StandardCharsets.ISO_8859_1);
                        newBody = newBody.substring(0, contentStart) + payloadContentStr + newBody.substring(boundaryIdx);
                    }
                }

                return baseRequest.withBody(newBody);
            }
        }

        // Fallback: replace body directly
        return baseRequest.withBody(ByteArray.byteArray(payload.getContent()));
    }
}
