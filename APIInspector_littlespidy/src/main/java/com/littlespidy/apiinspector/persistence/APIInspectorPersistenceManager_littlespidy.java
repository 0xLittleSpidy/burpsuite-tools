// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.GeneratedVariationItem;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.ReferenceRequestEntry;
import com.littlespidy.apiinspector.model.ProbeResult_littlespidy;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.*;
import com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy;
import com.littlespidy.apiinspector.ui.RequestSessionPanel_littlespidy;
import com.littlespidy.apiinspector.ui.ResAPIVersionFinderTab_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Manages persistent storage and state recovery for API Inspector sessions and
 * Intruder strategy tracking across extension reloads and Burp Suite restarts.
 */
public class APIInspectorPersistenceManager_littlespidy {

    public static final String PREF_KEY_STORAGE_DIR = "api_inspector_storage_dir";
    public static final String SESSION_FILENAME = "api_inspector_session.json";
    private static final String DEFAULT_FALLBACK_DIR = ".burp_api_inspector";

    private final MontoyaApi api;
    private final Gson gson;
    private File storageDirectory;

    private final ScheduledExecutorService debounceExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "APIInspector-Persistence-Thread");
        t.setDaemon(true);
        return t;
    });

    private ScheduledFuture<?> pendingSaveTask;
    private final Object saveLock = new Object();

    private APIInspectorTab_littlespidy rootTab;

    public APIInspectorPersistenceManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.rootTab = rootTab;
    }

    /**
     * Resolves the storage directory:
     * 1. If project file (.burp) is detected, uses its parent folder.
     * 2. Checks saved preferences for a remembered directory.
     * 3. Prompts the user with a native folder chooser dialog.
     * 4. Falls back to user home ~/.burp_api_inspector.
     */
    public synchronized File resolveStorageDirectory(Component parent) {
        if (storageDirectory != null && storageDirectory.exists()) {
            return storageDirectory;
        }

        // 1. Check for active Burp project file on disk
        File detectedProjectDir = detectBurpProjectDirectory();
        if (detectedProjectDir != null && detectedProjectDir.exists()) {
            this.storageDirectory = detectedProjectDir;
            log("[API Inspector] Using active Burp project directory: " + storageDirectory.getAbsolutePath());
            return storageDirectory;
        }

        // 2. Read saved preference
        String savedPrefDir = null;
        try {
            if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
                savedPrefDir = api.persistence().preferences().getString(PREF_KEY_STORAGE_DIR);
            }
        } catch (Exception ignored) {}

        // 3. Prompt user for storage directory
        File chosenDir = promptUserForDirectory(parent, savedPrefDir);
        if (chosenDir != null) {
            this.storageDirectory = chosenDir;
            try {
                if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
                    api.persistence().preferences().setString(PREF_KEY_STORAGE_DIR, chosenDir.getAbsolutePath());
                }
            } catch (Exception ignored) {}
            log("[API Inspector] Storage directory set to: " + storageDirectory.getAbsolutePath());
            return storageDirectory;
        }

        // 4. Use saved preference if valid
        if (savedPrefDir != null && !savedPrefDir.isBlank()) {
            File p = new File(savedPrefDir);
            if (p.exists() || p.mkdirs()) {
                this.storageDirectory = p;
                log("[API Inspector] Using remembered storage directory: " + storageDirectory.getAbsolutePath());
                return storageDirectory;
            }
        }

        // 5. Default fallback directory
        this.storageDirectory = new File(System.getProperty("user.home"), DEFAULT_FALLBACK_DIR);
        if (!storageDirectory.exists()) {
            storageDirectory.mkdirs();
        }
        log("[API Inspector] Using fallback storage directory: " + storageDirectory.getAbsolutePath());
        return storageDirectory;
    }

    public synchronized File promptUserForDirectory(Component parent, String initialDir) {
        if (GraphicsEnvironment.isHeadless()) {
            return (initialDir != null && !initialDir.isBlank()) ? new File(initialDir) : null;
        }

        final File[] result = new File[1];
        Runnable r = () -> {
            Component dialogParent = parent;
            if (dialogParent == null && api != null && api.userInterface() != null && api.userInterface().swingUtils() != null) {
                dialogParent = api.userInterface().swingUtils().suiteFrame();
            }

            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select Directory to Store API Inspector Session Data");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);

            if (initialDir != null && !initialDir.isBlank()) {
                File initFile = new File(initialDir);
                if (initFile.exists()) {
                    chooser.setSelectedFile(initFile);
                }
            } else {
                chooser.setCurrentDirectory(new File(System.getProperty("user.home")));
            }

            int opt = chooser.showOpenDialog(dialogParent);
            if (opt == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                result[0] = chooser.getSelectedFile();
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(r);
            } catch (Exception ex) {
                r.run();
            }
        }

        return result[0];
    }

    public synchronized void setStorageDirectory(File dir) {
        if (dir != null) {
            this.storageDirectory = dir;
            if (!storageDirectory.exists()) {
                storageDirectory.mkdirs();
            }
            try {
                if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
                    api.persistence().preferences().setString(PREF_KEY_STORAGE_DIR, dir.getAbsolutePath());
                }
            } catch (Exception ignored) {}
            log("[API Inspector] Storage directory updated to: " + storageDirectory.getAbsolutePath());
        }
    }

    public synchronized File getStorageDirectory() {
        if (storageDirectory == null) {
            storageDirectory = new File(System.getProperty("user.home"), DEFAULT_FALLBACK_DIR);
            if (!storageDirectory.exists()) {
                storageDirectory.mkdirs();
            }
        }
        return storageDirectory;
    }

    public File getSessionFile() {
        return new File(getStorageDirectory(), SESSION_FILENAME);
    }

    /**
     * Schedules a debounced asynchronous save (1500ms delay) for the entire root tab.
     */
    public synchronized void saveAsync(APIInspectorTab_littlespidy rootTab) {
        if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
            pendingSaveTask.cancel(false);
        }
        pendingSaveTask = debounceExecutor.schedule(() -> saveSync(rootTab), 1500, TimeUnit.MILLISECONDS);
    }

    public synchronized void saveAsync(ResAPIVersionFinderTab_littlespidy tab) {
        if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
            pendingSaveTask.cancel(false);
        }
        pendingSaveTask = debounceExecutor.schedule(() -> saveSync(tab), 1500, TimeUnit.MILLISECONDS);
    }

    public void saveSync(ResAPIVersionFinderTab_littlespidy tab) {
        if (this.rootTab != null) {
            saveSync(this.rootTab);
            return;
        }
        if (tab == null) return;
        saveSyncInternal(tab, null, null);
    }

    public void saveSync(APIInspectorTab_littlespidy rootTab) {
        if (rootTab == null) return;
        saveSyncInternal(rootTab.getVersionFinderTab(),
                rootTab.getDocStrategyTab().getAllEntries(),
                rootTab.getEndpointDiscoveryTab().getAllEntries());
    }

    private void saveSyncInternal(
            ResAPIVersionFinderTab_littlespidy tab,
            List<ReferenceRequestEntry> docEntries,
            List<ReferenceRequestEntry> endpointEntries) {

        synchronized (saveLock) {
            try {
                File sessionFile = getSessionFile();
                File parentDir = sessionFile.getParentFile();
                if (parentDir != null && !parentDir.exists()) {
                    parentDir.mkdirs();
                }

                SessionRootDTO root = new SessionRootDTO();
                root.savedAt = System.currentTimeMillis();

                if (tab != null) {
                    List<RequestSessionPanel_littlespidy> panels = tab.getAllSessionPanels();
                    for (int i = 0; i < panels.size(); i++) {
                        RequestSessionPanel_littlespidy panel = panels.get(i);
                        String tabTitle = tab.getTabTitleAt(i);
                        SessionTabDTO tabDTO = serializeSessionPanel(panel, tabTitle);
                        root.tabs.add(tabDTO);
                    }
                }

                if (docEntries != null) {
                    for (ReferenceRequestEntry ref : docEntries) {
                        root.documentationEntries.add(serializeReferenceRequest(ref));
                    }
                }

                if (endpointEntries != null) {
                    for (ReferenceRequestEntry ref : endpointEntries) {
                        root.endpointDiscoveryEntries.add(serializeReferenceRequest(ref));
                    }
                }

                String json = gson.toJson(root);
                File tmpFile = new File(parentDir, SESSION_FILENAME + ".tmp");
                Files.writeString(tmpFile.toPath(), json, StandardCharsets.UTF_8);

                try {
                    Files.move(tmpFile.toPath(), sessionFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmpFile.toPath(), sessionFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }

            } catch (Exception ex) {
                log("[API Inspector] Error saving session to disk: " + ex.getMessage());
            }
        }
    }

    /**
     * Loads saved sessions from disk and restores them into the given root tab.
     */
    public void loadSession(APIInspectorTab_littlespidy rootTab) {
        if (rootTab == null) return;
        synchronized (saveLock) {
            try {
                File sessionFile = getSessionFile();
                if (!sessionFile.exists() || sessionFile.length() == 0) {
                    return;
                }

                String json = Files.readString(sessionFile.toPath(), StandardCharsets.UTF_8);
                SessionRootDTO root = gson.fromJson(json, SessionRootDTO.class);
                if (root == null) return;

                SwingUtilities.invokeLater(() -> {
                    // 1. Restore ResAPI Version Finder tabs
                    if (root.tabs != null) {
                        for (SessionTabDTO tabDTO : root.tabs) {
                            rootTab.getVersionFinderTab().restoreSession(tabDTO);
                        }
                    }

                    // 2. Restore API Documentation Strategy entries
                    if (root.documentationEntries != null && !root.documentationEntries.isEmpty()) {
                        List<ReferenceRequestEntry> list = new ArrayList<>();
                        for (ReferenceRequestDTO rDto : root.documentationEntries) {
                            ReferenceRequestEntry ref = deserializeReferenceRequest(rDto);
                            if (ref != null) list.add(ref);
                        }
                        rootTab.getDocStrategyTab().restoreEntries(list);
                    }

                    // 3. Restore API Endpoint Discovery Strategy entries
                    if (root.endpointDiscoveryEntries != null && !root.endpointDiscoveryEntries.isEmpty()) {
                        List<ReferenceRequestEntry> list = new ArrayList<>();
                        for (ReferenceRequestDTO rDto : root.endpointDiscoveryEntries) {
                            ReferenceRequestEntry ref = deserializeReferenceRequest(rDto);
                            if (ref != null) list.add(ref);
                        }
                        rootTab.getEndpointDiscoveryTab().restoreEntries(list);
                    }

                    log("[API Inspector] Successfully restored session data from " + sessionFile.getAbsolutePath());
                });

            } catch (Exception ex) {
                log("[API Inspector] Error loading session from disk: " + ex.getMessage());
            }
        }
    }

    // --- Helper Serialization Methods ---

    public SessionTabDTO serializeSessionPanel(RequestSessionPanel_littlespidy panel, String tabTitle) {
        SessionTabDTO dto = new SessionTabDTO();
        dto.tabTitle = tabTitle;

        HttpRequest baseReq = panel.getBaselineRequest();
        if (baseReq != null) {
            dto.targetUrl = baseReq.url();
            dto.method = baseReq.method();
            dto.baselineRequest = serializeHttpRequest(baseReq);
        }

        HttpResponse baseResp = panel.getBaselineResponse();
        if (baseResp != null) {
            dto.baselineResponse = serializeHttpResponse(baseResp, baseReq != null ? baseReq.httpService() : null);
        }

        dto.strategies.uriPath = panel.isUriPathSelected();
        dto.strategies.headers = panel.isHeadersSelected();
        dto.strategies.queryParams = panel.isQueryParamsSelected();
        dto.strategies.contentNegotiation = panel.isContentNegotiationSelected();
        dto.strategies.subdomains = panel.isSubdomainsSelected();
        dto.strategies.cookies = panel.isCookiesSelected();

        dto.candidates = panel.getCandidatesText();
        dto.threads = panel.getThreadCount();
        dto.delayMs = panel.getDelayMs();

        for (ProbeResult_littlespidy r : panel.getTableModel().getAllResults()) {
            ProbeResultDTO prDto = new ProbeResultDTO();
            prDto.id = r.getId();
            prDto.strategyName = r.getStrategyName();
            prDto.variation = r.getVariation();
            prDto.statusCode = r.getStatusCode();
            prDto.responseLength = r.getResponseLength();
            prDto.mimeType = r.getMimeType();
            prDto.diffAnalysis = r.getDiffAnalysis();
            prDto.latencyMs = r.getLatencyMs();

            if (r.getRequest() != null) {
                prDto.request = serializeHttpRequest(r.getRequest());
            }
            if (r.getResponse() != null) {
                prDto.response = serializeHttpResponse(r.getResponse(), r.getRequest() != null ? r.getRequest().httpService() : null);
            }
            dto.results.add(prDto);
        }

        return dto;
    }

    public static ReferenceRequestDTO serializeReferenceRequest(ReferenceRequestEntry ref) {
        if (ref == null) return null;
        ReferenceRequestDTO dto = new ReferenceRequestDTO();
        dto.id = ref.getId();
        dto.timestamp = ref.getTimestamp();
        dto.strategyName = ref.getStrategyName();
        dto.method = ref.getMethod();
        dto.originalPath = ref.getOriginalPath();
        dto.host = ref.getHost();
        dto.fullUrl = ref.getFullUrl();
        dto.referenceRequest = serializeHttpRequest(ref.getReferenceRequest());

        for (GeneratedVariationItem var : ref.getVariations()) {
            GeneratedVariationDTO vDto = new GeneratedVariationDTO();
            vDto.variationIndex = var.getVariationIndex();
            vDto.pathVariation = var.getPathVariation();
            vDto.authenticated = var.isAuthenticated();
            vDto.intruderStatus = var.getIntruderStatus();
            vDto.fullUrl = var.getFullUrl();
            vDto.generatedRequest = serializeHttpRequest(var.getGeneratedRequest());
            dto.variations.add(vDto);
        }

        return dto;
    }

    public static ReferenceRequestEntry deserializeReferenceRequest(ReferenceRequestDTO dto) {
        if (dto == null) return null;
        HttpRequest refReq = deserializeHttpRequest(dto.referenceRequest);
        List<GeneratedVariationItem> vars = new ArrayList<>();
        if (dto.variations != null) {
            for (GeneratedVariationDTO vDto : dto.variations) {
                HttpRequest genReq = deserializeHttpRequest(vDto.generatedRequest);
                vars.add(new GeneratedVariationItem(
                        vDto.variationIndex,
                        vDto.pathVariation,
                        vDto.authenticated,
                        vDto.intruderStatus,
                        vDto.fullUrl,
                        genReq
                ));
            }
        }
        return new ReferenceRequestEntry(
                dto.id,
                dto.timestamp,
                dto.strategyName,
                dto.method,
                dto.originalPath,
                dto.host,
                dto.fullUrl,
                refReq,
                vars
        );
    }

    public static HttpMessageDTO serializeHttpRequest(HttpRequest req) {
        if (req == null) return null;
        HttpMessageDTO dto = new HttpMessageDTO();
        if (req.httpService() != null) {
            dto.host = req.httpService().host();
            dto.port = req.httpService().port();
            dto.secure = req.httpService().secure();
        }
        if (req.toByteArray() != null) {
            dto.base64Bytes = Base64.getEncoder().encodeToString(req.toByteArray().getBytes());
        }
        return dto;
    }

    public static HttpMessageDTO serializeHttpResponse(HttpResponse resp, HttpService service) {
        if (resp == null) return null;
        HttpMessageDTO dto = new HttpMessageDTO();
        if (service != null) {
            dto.host = service.host();
            dto.port = service.port();
            dto.secure = service.secure();
        }
        if (resp.toByteArray() != null) {
            dto.base64Bytes = Base64.getEncoder().encodeToString(resp.toByteArray().getBytes());
        }
        return dto;
    }

    public static HttpRequest deserializeHttpRequest(HttpMessageDTO dto) {
        if (dto == null || dto.base64Bytes == null) return null;
        try {
            byte[] bytes = Base64.getDecoder().decode(dto.base64Bytes);
            HttpService service = (dto.host != null && !dto.host.isBlank())
                    ? HttpService.httpService(dto.host, dto.port > 0 ? dto.port : (dto.secure ? 443 : 80), dto.secure)
                    : null;
            if (service != null) {
                return HttpRequest.httpRequest(service, ByteArray.byteArray(bytes));
            } else {
                return HttpRequest.httpRequest(ByteArray.byteArray(bytes));
            }
        } catch (Exception ex) {
            return null;
        }
    }

    public static HttpResponse deserializeHttpResponse(HttpMessageDTO dto) {
        if (dto == null || dto.base64Bytes == null) return null;
        try {
            byte[] bytes = Base64.getDecoder().decode(dto.base64Bytes);
            return HttpResponse.httpResponse(ByteArray.byteArray(bytes));
        } catch (Exception ex) {
            return null;
        }
    }

    private File detectBurpProjectDirectory() {
        if (api == null) return null;
        try {
            List<String> args = api.burpSuite().commandLineArguments();
            if (args != null) {
                for (int i = 0; i < args.size(); i++) {
                    String arg = args.get(i);
                    if (arg.startsWith("--project-file=")) {
                        String filePath = arg.substring("--project-file=".length()).trim();
                        File p = new File(filePath);
                        if (p.getParentFile() != null && p.getParentFile().exists()) {
                            return p.getParentFile();
                        }
                    } else if ("--project-file".equals(arg) && i + 1 < args.size()) {
                        String filePath = args.get(i + 1).trim();
                        File p = new File(filePath);
                        if (p.getParentFile() != null && p.getParentFile().exists()) {
                            return p.getParentFile();
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        try {
            Frame frame = api.userInterface() != null && api.userInterface().swingUtils() != null
                    ? api.userInterface().swingUtils().suiteFrame()
                    : null;
            if (frame != null) {
                String title = frame.getTitle();
                if (title != null && !title.isBlank() && !title.contains("Temporary Project")) {
                    int burpIdx = title.lastIndexOf(".burp");
                    if (burpIdx > 0) {
                        int startIdx = title.lastIndexOf(" - ", burpIdx);
                        String cand = (startIdx != -1) ? title.substring(startIdx + 3, burpIdx + 5).trim() : title.substring(0, burpIdx + 5).trim();
                        File f = new File(cand);
                        if (f.exists()) {
                            return f.getParentFile();
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        return null;
    }

    private void log(String message) {
        if (api != null && api.logging() != null) {
            api.logging().logToOutput(message);
        } else {
            System.out.println(message);
        }
    }
}
