package com.littlespidy.uploadscanner.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpHeader;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
        startInternal(baseRequest, false);
    }

    public void startAllowedExtensionsProbe(HttpRequest baseRequest) {
        startInternal(baseRequest, true);
    }

    private void startInternal(HttpRequest baseRequest, boolean probeOnly) {
        if (running.get()) {
            return;
        }

        running.set(true);
        paused.set(false);
        statusConsumer.accept(probeOnly ? "Starting allowed extensions probe..." : "Starting scan...");

        worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    executeScan(baseRequest, probeOnly);
                } catch (Exception e) {
                    api.logging().logToError("Error during upload scan: " + e.getMessage());
                }
                return null;
            }

            @Override
            protected void done() {
                running.set(false);
                statusConsumer.accept(probeOnly ? "Allowed extensions probe finished." : "Scan finished.");
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        };

        worker.execute();
    }

    private void executeScan(HttpRequest baseRequest, boolean probeOnly) {
        ReDownloaderEngine redlEngine = new ReDownloaderEngine(api, config.getRedownloaderConfig());
        String originalFilename = extractFilenameFromRequest(baseRequest);

        CollaboratorClient collaboratorClient = null;
        String collaboratorDomain = "";
        if (!probeOnly) {
            try {
                if (api.collaborator() != null) {
                    collaboratorClient = api.collaborator().createClient();
                    if (collaboratorClient != null) {
                        collaboratorDomain = collaboratorClient.generatePayload().toString();
                    }
                }
            } catch (Throwable t) {
                collaboratorDomain = "collab-test.burpcollaborator.net";
            }
        }

        List<PayloadDefinition> payloads = probeOnly
                ? UploadPayloadGenerator.generateAllowedExtensionPayloadsOnly(config, originalFilename)
                : UploadPayloadGenerator.generatePayloads(config, originalFilename, collaboratorDomain);

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

            // Fallback: Smart Auto-Detect from response if not matched by custom markers
            if (!extraction.isFound() && uploadPair.hasResponse()) {
                ReDownloaderEngine.DetectionResult autoDet =
                        redlEngine.autoDetectDownloadUrl(uploadPair.response(), payload.getFilename());
                if (autoDet.isFound()) {
                    extraction = new MarkerHighlighter.ExtractionResult(
                            true, autoDet.getDetectedUrl(), 0, 0, 0, autoDet.getDetectedUrl().length());
                }
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
            StageType entryStage = (probeOnly || "Allowed Extensions".equalsIgnoreCase(payload.getCategory()))
                    ? StageType.EXTENSION_PROBE
                    : StageType.UPLOAD;
            UploadEntry uploadEntry = new UploadEntry(
                    uploadId,
                    entryStage,
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

        // ── Step 4: Poll Out-of-Band Collaborator Interactions ──
        if (collaboratorClient != null) {
            try {
                // Brief pause to allow DNS/HTTP propagation
                Thread.sleep(600);
                List<Interaction> interactions = collaboratorClient.getAllInteractions();
                for (Interaction interaction : interactions) {
                    int oobId = sequenceCounter.getAndIncrement();
                    String clientIp = (interaction.clientIp() != null) ? interaction.clientIp().getHostAddress() : "unknown";
                    String desc = "🔥 Collaborator OOB: " + interaction.type().name() + " callback from " + clientIp;
                    UploadEntry oobEntry = new UploadEntry(
                            oobId,
                            StageType.VERIFICATION,
                            interaction.type().name(),
                            (short) 200,
                            desc,
                            0,
                            "http://" + collaboratorDomain,
                            null,
                            interaction.type().name() + " callback received",
                            null,
                            null
                    );
                    publishEntry(oobEntry);
                }
            } catch (Throwable ignored) {}
        }
    }

    private void publishEntry(UploadEntry entry) {
        SwingUtilities.invokeLater(() -> entryConsumer.accept(entry));
    }

    public static String extractFilenameFromRequest(HttpRequest request) {
        if (request == null) return "upload.jpg";

        // 1. Check if §...§ marker exists in path
        String path = request.path();
        Matcher pm = Pattern.compile("§([^§]+)§").matcher(path);
        if (pm.find()) {
            String val = pm.group(1).trim();
            if (!val.isEmpty() && !val.equalsIgnoreCase("filename") && !val.equalsIgnoreCase("file")) {
                return val;
            }
        }

        // 2. Check if §...§ marker exists in body
        String body = request.bodyToString();
        Matcher bm = Pattern.compile("§([^§]+)§").matcher(body);
        if (bm.find()) {
            String val = bm.group(1).trim();
            if (!val.isEmpty() && !val.equalsIgnoreCase("filename") && !val.equalsIgnoreCase("file")) {
                return val;
            }
        }

        // 3. Fallback: filename="..."
        int idx = body.indexOf("filename=\"");
        if (idx != -1) {
            int end = body.indexOf("\"", idx + 10);
            if (end != -1) {
                return body.substring(idx + 10, end).replace("§", "").trim();
            }
        }
        return "upload.jpg";
    }

    public static HttpRequest injectPayload(HttpRequest baseRequest, PayloadDefinition payload) {
        if (baseRequest == null) return null;

        String payloadFilename = payload.getFilename();
        HttpRequest modifiedReq = baseRequest;

        // 1. Check and replace §...§ markers in Path / Query String
        String path = modifiedReq.path();
        if (path.contains("§") || path.contains("${FILENAME}")) {
            String newPath = path.replaceAll("§[^§]*§", Matcher.quoteReplacement(payloadFilename))
                                 .replace("${FILENAME}", payloadFilename);
            modifiedReq = modifiedReq.withPath(newPath);
        }

        // 2. Check and replace §...§ markers in Headers
        List<HttpHeader> headers = modifiedReq.headers();
        for (HttpHeader h : headers) {
            String hVal = h.value();
            if (hVal.contains("§") || hVal.contains("${FILENAME}")) {
                String newHVal = hVal.replaceAll("§[^§]*§", Matcher.quoteReplacement(payloadFilename))
                                     .replace("${FILENAME}", payloadFilename);
                modifiedReq = modifiedReq.withHeader(h.name(), newHVal);
            }
        }

        // 3. Check and replace in Body
        String body = modifiedReq.bodyToString();
        boolean hasBodyMarkers = body.contains("§") || body.contains("${FILENAME}");

        if (hasBodyMarkers) {
            body = body.replaceAll("§[^§]*§", Matcher.quoteReplacement(payloadFilename))
                       .replace("${FILENAME}", payloadFilename);
        }

        // 4. Handle multipart file content and Content-Type injection
        int fnIdx = body.indexOf("filename=\"");
        if (fnIdx != -1) {
            int fnEnd = body.indexOf("\"", fnIdx + 10);
            if (fnEnd != -1) {
                String newBody;
                if (!hasBodyMarkers) {
                    newBody = body.substring(0, fnIdx + 10) + payloadFilename + body.substring(fnEnd);
                } else {
                    newBody = body;
                }

                // Look for Content-Type within this multipart part
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

                return modifiedReq.withBody(newBody);
            }
        }

        if (hasBodyMarkers) {
            return modifiedReq.withBody(body);
        }

        // Fallback: replace body directly with binary payload
        return modifiedReq.withBody(ByteArray.byteArray(payload.getContent()));
    }
}
