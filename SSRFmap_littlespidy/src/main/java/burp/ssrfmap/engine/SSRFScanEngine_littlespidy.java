// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.ssrfmap.model.SSRFResultEntry_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadItem_littlespidy;
import burp.ssrfmap.ui.MarkerRequestEditor_littlespidy;
import burp.ssrfmap.ui.SSRFTableModel_littlespidy;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.SwingUtilities;

public class SSRFScanEngine_littlespidy {

    public interface ScanProgressListener {
        void onProgress(int current, int total);
        void onStatusChanged(String statusText);
        void onFinished();
    }

    private final MontoyaApi api;
    private final HttpService httpService;
    private final MarkerRequestEditor_littlespidy requestEditor;
    private final SSRFTableModel_littlespidy tableModel;
    private final CollaboratorManager_littlespidy collaboratorManager;
    private final List<SSRFPayloadItem_littlespidy> payloadQueue;
    private final int concurrency;
    private final int delayMs;
    private final boolean useCollaborator;
    private final boolean useDiff;
    private final ScanProgressListener listener;

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicBoolean isPaused = new AtomicBoolean(false);
    private final AtomicBoolean isStopped = new AtomicBoolean(false);
    private ExecutorService threadPool;

    public SSRFScanEngine_littlespidy(
            MontoyaApi api,
            HttpService httpService,
            MarkerRequestEditor_littlespidy requestEditor,
            SSRFTableModel_littlespidy tableModel,
            CollaboratorManager_littlespidy collaboratorManager,
            List<SSRFPayloadItem_littlespidy> payloadQueue,
            int concurrency,
            int delayMs,
            boolean useCollaborator,
            boolean useDiff,
            ScanProgressListener listener) {
        this.api = api;
        this.httpService = httpService;
        this.requestEditor = requestEditor;
        this.tableModel = tableModel;
        this.collaboratorManager = collaboratorManager;
        this.payloadQueue = payloadQueue;
        this.concurrency = Math.max(1, concurrency);
        this.delayMs = Math.max(0, delayMs);
        this.useCollaborator = useCollaborator;
        this.useDiff = useDiff;
        this.listener = listener;
    }

    public void start() {
        if (!isRunning.compareAndSet(false, true)) {
            return;
        }

        Thread masterThread = new Thread(this::runScanWorkflow, "SSRFmap-Master-Thread");
        masterThread.setDaemon(true);
        masterThread.start();
    }

    public void pause() {
        isPaused.set(true);
        if (listener != null) {
            listener.onStatusChanged("Paused");
        }
    }

    public void resume() {
        isPaused.set(false);
        if (listener != null) {
            listener.onStatusChanged("Running");
        }
    }

    public void stop() {
        isStopped.set(true);
        isPaused.set(false);
        if (threadPool != null) {
            threadPool.shutdownNow();
        }
        isRunning.set(false);
        if (listener != null) {
            listener.onStatusChanged("Stopped");
            listener.onFinished();
        }
    }

    public boolean isRunning() {
        return isRunning.get();
    }

    public boolean isPaused() {
        return isPaused.get();
    }

    private void runScanWorkflow() {
        try {
            if (listener != null) {
                listener.onStatusChanged("Sending baseline request...");
            }

            // 1. Baseline Request
            String cleanBaseline = requestEditor.getCleanBaselineRequest();
            HttpRequest baselineReq = HttpRequest.httpRequest(httpService, cleanBaseline);
            long startBase = System.currentTimeMillis();
            HttpRequestResponse baseReqResp = api.http().sendRequest(baselineReq);
            long baseLatency = System.currentTimeMillis() - startBase;

            HttpResponse baseResp = baseReqResp.response();
            int baseStatusCode = baseResp != null ? (int) baseResp.statusCode() : 0;
            String baseBody = baseResp != null ? baseResp.bodyToString() : "";
            int baseLength = baseResp != null ? baseResp.toByteArray().length() : 0;

            SSRFResultEntry_littlespidy baseEntry = new SSRFResultEntry_littlespidy(
                    0,
                    "baseline",
                    "original",
                    requestEditor.getMarkedParameterValue(),
                    baseStatusCode,
                    baseLength,
                    baseLatency,
                    "Original baseline (" + baseLength + " B)",
                    "None",
                    "BASELINE",
                    baseReqResp,
                    "Baseline request - reference profile."
            );

            SwingUtilities.invokeLater(() -> tableModel.addEntry(baseEntry));

            // 2. Prepare Payload Execution
            int total = payloadQueue.size();
            AtomicInteger completedCounter = new AtomicInteger(0);

            threadPool = Executors.newFixedThreadPool(concurrency);

            for (int i = 0; i < total; i++) {
                final int currentId = i + 1;
                final SSRFPayloadItem_littlespidy payloadItem = payloadQueue.get(i);

                threadPool.submit(() -> {
                    if (isStopped.get()) {
                        return;
                    }

                    while (isPaused.get() && !isStopped.get()) {
                        try {
                            Thread.sleep(200);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }

                    if (isStopped.get()) {
                        return;
                    }

                    executeSinglePayload(currentId, payloadItem, baseBody, baseStatusCode);

                    int done = completedCounter.incrementAndGet();
                    if (listener != null) {
                        listener.onProgress(done, total);
                    }

                    if (delayMs > 0) {
                        try {
                            Thread.sleep(delayMs);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                });
            }

            threadPool.shutdown();
            while (!threadPool.isTerminated()) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            // 3. Post-scan Collaborator poll
            if (useCollaborator && collaboratorManager != null && collaboratorManager.isAvailable() && !isStopped.get()) {
                if (listener != null) {
                    listener.onStatusChanged("Polling Collaborator interactions...");
                }
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ignored) {}

                pollAndTagCollaboratorInteractions();
            }

            if (listener != null) {
                listener.onStatusChanged("Scan finished (" + completedCounter.get() + "/" + total + " completed)");
                listener.onFinished();
            }

        } catch (Exception e) {
            if (listener != null) {
                listener.onStatusChanged("Error: " + e.getMessage());
                listener.onFinished();
            }
        } finally {
            isRunning.set(false);
        }
    }

    private void executeSinglePayload(
            int id,
            SSRFPayloadItem_littlespidy payloadItem,
            String baselineBody,
            int baselineStatusCode) {

        String concretePayload = payloadItem.getPayloadTemplate();
        String collabHost = null;

        if (payloadItem.isRequiresCollaborator() && useCollaborator && collaboratorManager != null) {
            collabHost = collaboratorManager.generatePayloadForId(id);
            concretePayload = concretePayload.replace("{COLLABORATOR_HOST}", collabHost);
        } else {
            concretePayload = concretePayload.replace("{COLLABORATOR_HOST}", "127.0.0.1");
        }

        concretePayload = concretePayload.replace("{TARGET_HOST}", httpService.host());

        String modifiedRequestStr = requestEditor.buildRequestWithPayload(concretePayload);
        HttpRequest req = HttpRequest.httpRequest(httpService, modifiedRequestStr);

        long start = System.currentTimeMillis();
        HttpRequestResponse reqResp;
        try {
            reqResp = api.http().sendRequest(req);
        } catch (Exception e) {
            SSRFResultEntry_littlespidy errEntry = new SSRFResultEntry_littlespidy(
                    id,
                    payloadItem.getModuleName(),
                    payloadItem.getScheme(),
                    concretePayload,
                    0,
                    0,
                    System.currentTimeMillis() - start,
                    "Connection error: " + e.getMessage(),
                    "None",
                    "ERROR",
                    null,
                    "Request dispatch failed: " + e.getMessage()
            );
            SwingUtilities.invokeLater(() -> tableModel.addEntry(errEntry));
            return;
        }

        long latency = System.currentTimeMillis() - start;
        HttpResponse resp = reqResp != null ? reqResp.response() : null;
        int statusCode = resp != null ? (int) resp.statusCode() : 0;
        int length = resp != null ? resp.toByteArray().length() : 0;
        String respBody = resp != null ? resp.bodyToString() : "";

        DiffAnalyzer_littlespidy.AnalysisResult diffResult = DiffAnalyzer_littlespidy.analyze(
                baselineBody,
                baselineStatusCode,
                respBody,
                statusCode,
                payloadItem.getExpectedIndicators()
        );

        String resultStatus = "PROBED";
        if (!diffResult.getMatchedIndicators().isEmpty()) {
            resultStatus = "VULNERABLE";
        } else if (diffResult.isSignificantDiff() && useDiff) {
            resultStatus = "DIFF DETECTED";
        }

        String collabInfo = "None";
        if (collabHost != null) {
            collabInfo = "Subdomain: " + collabHost;
        }

        SSRFResultEntry_littlespidy entry = new SSRFResultEntry_littlespidy(
                id,
                payloadItem.getModuleName(),
                payloadItem.getScheme(),
                concretePayload,
                statusCode,
                length,
                latency,
                diffResult.getDiffSummary(),
                collabInfo,
                resultStatus,
                reqResp,
                diffResult.getLineDiff()
        );

        SwingUtilities.invokeLater(() -> tableModel.addEntry(entry));
    }

    private void pollAndTagCollaboratorInteractions() {
        List<SSRFResultEntry_littlespidy> entries = tableModel.getAllEntries();
        for (int i = 0; i < entries.size(); i++) {
            SSRFResultEntry_littlespidy entry = entries.get(i);
            if (entry.getId() <= 0) continue;

            List<Interaction> interactions = collaboratorManager.pollInteractionsForId(entry.getId());
            if (interactions != null && !interactions.isEmpty()) {
                StringBuilder details = new StringBuilder();
                String firstType = "Interaction";
                for (Interaction interaction : interactions) {
                    firstType = interaction.type().name();
                    details.append("Type: ").append(interaction.type().name())
                           .append("\nClient IP: ").append(interaction.clientIp().getHostAddress())
                           .append("\nTimestamp: ").append(interaction.timeStamp().toString())
                           .append("\n---\n");
                }
                entry.setCollaboratorInfo(firstType + " (" + interactions.size() + " events)");
                entry.setStatus("COLLAB HIT");
                entry.setCollaboratorInteractionDetails(details.toString());

                final int rowIndex = i;
                SwingUtilities.invokeLater(() -> tableModel.updateEntry(rowIndex));
            }
        }
    }
}
