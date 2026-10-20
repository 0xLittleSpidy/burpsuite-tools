// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.headerinspector.cache.model.CacheDataStore;
import com.littlespidy.headerinspector.cache.model.CacheEntry;
import com.littlespidy.headerinspector.collector.model.HeaderCollectorDataStore;
import com.littlespidy.headerinspector.csp.model.CSPDataStore;
import com.littlespidy.headerinspector.csp.model.CSPEntry;
import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.hsts.model.HSTSEntry;
import com.littlespidy.headerinspector.method.model.MethodCollectorDataStore;
import com.littlespidy.headerinspector.status.model.StatusCollectorDataStore;
import com.littlespidy.headerinspector.storage.HeaderSessionDTO_littlespidy.*;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for Header Inspector.
 * Coordinates all sub-datastores: Header Collector, Method Collector, Status Collector,
 * Cache, CSP, and HSTS.
 */
public class HeaderPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "HeaderInspector-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private ScheduledFuture<?> scheduledSaveTask = null;

    private HeaderCollectorDataStore headerDataStore;
    private MethodCollectorDataStore methodDataStore;
    private StatusCollectorDataStore statusDataStore;
    private CacheDataStore cacheDataStore;
    private CSPDataStore cspDataStore;
    private HSTSDataStore hstsDataStore;

    private final JLabel sessionStatusLabel;

    public HeaderPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    }

    public void bindDataStores(
            HeaderCollectorDataStore headerDataStore,
            MethodCollectorDataStore methodDataStore,
            StatusCollectorDataStore statusDataStore,
            CacheDataStore cacheDataStore,
            CSPDataStore cspDataStore,
            HSTSDataStore hstsDataStore
    ) {
        this.headerDataStore = headerDataStore;
        this.methodDataStore = methodDataStore;
        this.statusDataStore = statusDataStore;
        this.cacheDataStore = cacheDataStore;
        this.cspDataStore = cspDataStore;
        this.hstsDataStore = hstsDataStore;
    }

    public void initializeSessionOnStartup(Component parent, Runnable onRefresh) {
        SessionStartupDialog_littlespidy.StartupResult result = SessionStartupDialog_littlespidy.promptUser(api, parent);
        switch (result.action()) {
            case OPEN_EXISTING -> openSessionFile(result.sessionFile());
            case CREATE_NEW -> createNewSessionFile(result.sessionFile());
            case TEMPORARY -> startTemporarySession();
        }
        if (onRefresh != null) {
            SwingUtilities.invokeLater(onRefresh);
        }
    }

    public synchronized void resetAllStores() {
        if (headerDataStore != null) headerDataStore.clear();
        if (methodDataStore != null) methodDataStore.clear();
        if (statusDataStore != null) statusDataStore.clear();
        if (cacheDataStore != null) cacheDataStore.clear();
        if (cspDataStore != null) cspDataStore.clear();
        if (hstsDataStore != null) hstsDataStore.clear();
    }

    public synchronized void openSessionFile(File file) {
        if (file == null || !file.exists()) return;
        try {
            String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            SessionRootDTO root = gson.fromJson(json, SessionRootDTO.class);
            if (root == null) {
                throw new IllegalStateException("Corrupted or empty session JSON file.");
            }

            resetAllStores();

            // 1. Restore Cache Entries
            List<CacheEntry> restoredCache = new ArrayList<>();
            if (root.cacheEntries != null) {
                for (CacheEntryDTO dto : root.cacheEntries) {
                    HttpRequest req = reconstructRequest(dto.hasRequest, dto.requestBase64, dto.requestHost, dto.requestPort, dto.requestSecure);
                    HttpResponse resp = reconstructResponse(dto.hasResponse, dto.responseBase64);
                    ZonedDateTime ts = parseTimestamp(dto.timestamp);

                    CacheEntry entry = new CacheEntry(
                            dto.id, dto.url, dto.host, dto.path, dto.method,
                            dto.statusCode, dto.contentType, dto.cacheControl, dto.pragma,
                            dto.expires, dto.age, dto.etag, dto.lastModified, dto.vary,
                            dto.xCache, dto.xCacheHits, dto.cdnCacheControl, dto.surrogateControl,
                            dto.cfCacheStatus, req, resp, ts
                    );
                    restoredCache.add(entry);

                    if (req != null || resp != null) {
                        ProxyHttpRequestResponse item = new ProxyHttpRequestResponseAdapter_littlespidy(req, resp, ts);
                        if (headerDataStore != null) headerDataStore.ingest(item);
                        if (methodDataStore != null) methodDataStore.ingest(item);
                        if (statusDataStore != null && resp != null) statusDataStore.ingest(item);
                    }
                }
            }
            if (cacheDataStore != null) {
                cacheDataStore.addEntries(restoredCache);
            }

            // 2. Restore CSP Entries
            List<CSPEntry> restoredCsp = new ArrayList<>();
            if (root.cspEntries != null) {
                for (CSPEntryDTO dto : root.cspEntries) {
                    HttpRequest req = reconstructRequest(dto.hasRequest, dto.requestBase64, dto.requestHost, dto.requestPort, dto.requestSecure);
                    HttpResponse resp = reconstructResponse(dto.hasResponse, dto.responseBase64);
                    ZonedDateTime ts = parseTimestamp(dto.timestamp);

                    CSPEntry entry = new CSPEntry(
                            dto.id, dto.url, dto.host, dto.path, dto.method,
                            dto.statusCode, dto.contentType, dto.cspHeader, dto.cspReportOnlyHeader,
                            dto.xCspHeader, dto.xWebKitCspHeader, dto.parsedDirectives,
                            req, resp, ts
                    );
                    restoredCsp.add(entry);
                }
            }
            if (cspDataStore != null) {
                cspDataStore.addEntries(restoredCsp);
            }

            // 3. Restore HSTS Entries
            List<HSTSEntry> restoredHsts = new ArrayList<>();
            if (root.hstsEntries != null) {
                for (HSTSEntryDTO dto : root.hstsEntries) {
                    HttpRequest req = reconstructRequest(dto.hasRequest, dto.requestBase64, dto.requestHost, dto.requestPort, dto.requestSecure);
                    HttpResponse resp = reconstructResponse(dto.hasResponse, dto.responseBase64);
                    ZonedDateTime ts = parseTimestamp(dto.timestamp);

                    HSTSEntry entry = new HSTSEntry(
                            dto.id, dto.url, dto.host, dto.path, dto.method,
                            dto.statusCode, dto.contentType, dto.rawHeader, dto.maxAge,
                            dto.includeSubDomains, dto.preload, req, resp, ts
                    );
                    restoredHsts.add(entry);
                }
            }
            if (hstsDataStore != null) {
                hstsDataStore.addEntries(restoredHsts);
            }

            this.activeSessionFile = file;
            this.dirty.set(false);
            updateStatusLabel();
            log("[Header Inspector] Session opened successfully from: " + file.getAbsolutePath());
        } catch (Exception ex) {
            logError("[Header Inspector] Failed to open session from " + file.getAbsolutePath() + ": " + ex.getMessage());
            JOptionPane.showMessageDialog(null, "Failed to load session file:\n" + ex.getMessage(), "Session Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public synchronized void createNewSessionFile(File file) {
        if (file == null) return;
        resetAllStores();
        this.activeSessionFile = file;
        this.dirty.set(true);
        saveNow();
        updateStatusLabel();
        log("[Header Inspector] Created new session bound to: " + file.getAbsolutePath());
    }

    public synchronized void startTemporarySession() {
        resetAllStores();
        this.activeSessionFile = null;
        this.dirty.set(false);
        updateStatusLabel();
        log("[Header Inspector] Started temporary in-memory session.");
    }

    public synchronized void offboardSession(Component parent, Runnable onRefresh) {
        if (activeSessionFile == null) {
            resetAllStores();
            if (onRefresh != null) SwingUtilities.invokeLater(onRefresh);
            return;
        }

        if (dirty.get()) {
            int choice = JOptionPane.showConfirmDialog(
                    parent,
                    "Save pending changes to active session before offboarding?",
                    "Offboard Session - Unsaved Changes",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (choice == JOptionPane.CANCEL_OPTION) {
                return;
            }
            if (choice == JOptionPane.YES_OPTION) {
                saveNow();
            }
        }

        if (scheduledSaveTask != null) {
            scheduledSaveTask.cancel(false);
            scheduledSaveTask = null;
        }

        File previousFile = this.activeSessionFile;
        this.activeSessionFile = null;
        this.dirty.set(false);

        resetAllStores();

        updateStatusLabel();
        if (onRefresh != null) {
            SwingUtilities.invokeLater(onRefresh);
        }
        log("[Header Inspector] Offboarded session " + (previousFile != null ? previousFile.getName() : "") + ". Restored fresh clean state.");
    }

    public void scheduleAutoSave() {
        this.dirty.set(true);
        if (activeSessionFile == null) return;

        synchronized (this) {
            if (scheduledSaveTask != null && !scheduledSaveTask.isDone()) {
                scheduledSaveTask.cancel(false);
            }
            scheduledSaveTask = autoSaveExecutor.schedule(this::saveNow, 1500, TimeUnit.MILLISECONDS);
        }
    }

    public synchronized void saveNow() {
        if (activeSessionFile == null) return;
        try {
            SessionRootDTO root = new SessionRootDTO();
            root.savedAt = Instant.now().toString();

            if (cacheDataStore != null) {
                for (CacheEntry e : cacheDataStore.getEntries()) {
                    CacheEntryDTO dto = new CacheEntryDTO();
                    dto.id = e.id();
                    dto.url = e.url();
                    dto.host = e.host();
                    dto.path = e.path();
                    dto.method = e.method();
                    dto.statusCode = e.statusCode();
                    dto.contentType = e.contentType();
                    dto.cacheControl = e.cacheControl();
                    dto.pragma = e.pragma();
                    dto.expires = e.expires();
                    dto.age = e.age();
                    dto.etag = e.etag();
                    dto.lastModified = e.lastModified();
                    dto.vary = e.vary();
                    dto.xCache = e.xCache();
                    dto.xCacheHits = e.xCacheHits();
                    dto.cdnCacheControl = e.cdnCacheControl();
                    dto.surrogateControl = e.surrogateControl();
                    dto.cfCacheStatus = e.cfCacheStatus();
                    dto.timestamp = e.timestamp() != null ? e.timestamp().toString() : "";

                    if (e.request() != null) {
                        dto.hasRequest = true;
                        dto.requestBase64 = Base64.getEncoder().encodeToString(e.request().toByteArray().getBytes());
                        if (e.request().httpService() != null) {
                            dto.requestHost = e.request().httpService().host();
                            dto.requestPort = e.request().httpService().port();
                            dto.requestSecure = e.request().httpService().secure();
                        }
                    }
                    if (e.response() != null) {
                        dto.hasResponse = true;
                        dto.responseBase64 = Base64.getEncoder().encodeToString(e.response().toByteArray().getBytes());
                    }
                    root.cacheEntries.add(dto);
                }
            }

            if (cspDataStore != null) {
                for (CSPEntry e : cspDataStore.getEntries()) {
                    CSPEntryDTO dto = new CSPEntryDTO();
                    dto.id = e.id();
                    dto.url = e.url();
                    dto.host = e.host();
                    dto.path = e.path();
                    dto.method = e.method();
                    dto.statusCode = e.statusCode();
                    dto.contentType = e.contentType();
                    dto.cspHeader = e.cspHeader();
                    dto.cspReportOnlyHeader = e.cspReportOnlyHeader();
                    dto.xCspHeader = e.xCspHeader();
                    dto.xWebKitCspHeader = e.xWebKitCspHeader();
                    dto.parsedDirectives = e.parsedDirectives();
                    dto.timestamp = e.timestamp() != null ? e.timestamp().toString() : "";

                    if (e.request() != null) {
                        dto.hasRequest = true;
                        dto.requestBase64 = Base64.getEncoder().encodeToString(e.request().toByteArray().getBytes());
                        if (e.request().httpService() != null) {
                            dto.requestHost = e.request().httpService().host();
                            dto.requestPort = e.request().httpService().port();
                            dto.requestSecure = e.request().httpService().secure();
                        }
                    }
                    if (e.response() != null) {
                        dto.hasResponse = true;
                        dto.responseBase64 = Base64.getEncoder().encodeToString(e.response().toByteArray().getBytes());
                    }
                    root.cspEntries.add(dto);
                }
            }

            if (hstsDataStore != null) {
                for (HSTSEntry e : hstsDataStore.getEntries()) {
                    HSTSEntryDTO dto = new HSTSEntryDTO();
                    dto.id = e.id();
                    dto.url = e.url();
                    dto.host = e.host();
                    dto.path = e.path();
                    dto.method = e.method();
                    dto.statusCode = e.statusCode();
                    dto.rawHeader = e.hstsHeader();
                    dto.contentType = e.contentType();
                    dto.maxAge = e.maxAge();
                    dto.includeSubDomains = e.includeSubDomains();
                    dto.preload = e.preload();
                    dto.assessment = e.assessment();
                    dto.timestamp = e.timestamp() != null ? e.timestamp().toString() : "";

                    if (e.request() != null) {
                        dto.hasRequest = true;
                        dto.requestBase64 = Base64.getEncoder().encodeToString(e.request().toByteArray().getBytes());
                        if (e.request().httpService() != null) {
                            dto.requestHost = e.request().httpService().host();
                            dto.requestPort = e.request().httpService().port();
                            dto.requestSecure = e.request().httpService().secure();
                        }
                    }
                    if (e.response() != null) {
                        dto.hasResponse = true;
                        dto.responseBase64 = Base64.getEncoder().encodeToString(e.response().toByteArray().getBytes());
                    }
                    root.hstsEntries.add(dto);
                }
            }

            String json = gson.toJson(root);
            File parentDir = activeSessionFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            File tempFile = new File(activeSessionFile.getAbsolutePath() + ".tmp");
            Files.writeString(tempFile.toPath(), json, StandardCharsets.UTF_8);
            try {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }

            dirty.set(false);
            updateStatusLabel();
        } catch (Exception ex) {
            logError("[Header Inspector] Error saving session to " + activeSessionFile.getAbsolutePath() + ": " + ex.getMessage());
        }
    }

    public synchronized void saveAs(Component parent) {
        JFileChooser chooser = new JFileChooser(getLastDirectory());
        chooser.setDialogTitle("Save Header Inspector Session As");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        int res = chooser.showSaveDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            rememberDirectory(sel.getParent());
            this.activeSessionFile = sel;
            this.dirty.set(true);
            saveNow();
            updateStatusLabel();
            log("[Header Inspector] Session saved as: " + sel.getAbsolutePath());
        }
    }

    public JPanel createSessionToolbarComponent(Component parent, Runnable onRefresh) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JButton newBtn = new JButton("New Session");
        newBtn.addActionListener(e -> {
            if (dirty.get() && activeSessionFile != null) {
                int res = JOptionPane.showConfirmDialog(parent, "Save current session before creating a new one?", "Unsaved Changes", JOptionPane.YES_NO_CANCEL_OPTION);
                if (res == JOptionPane.YES_OPTION) saveNow();
                else if (res == JOptionPane.CANCEL_OPTION) return;
            }
            JFileChooser dirChooser = new JFileChooser(getLastDirectory());
            dirChooser.setDialogTitle("Select Directory For New Session");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (dirChooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION && dirChooser.getSelectedFile() != null) {
                File dir = dirChooser.getSelectedFile();
                rememberDirectory(dir.getAbsolutePath());
                String name = JOptionPane.showInputDialog(parent, "Enter session filename:", "header_inspector_session.json");
                if (name != null && !name.isBlank()) {
                    if (!name.toLowerCase().endsWith(".json")) name += ".json";
                    createNewSessionFile(new File(dir, name.trim()));
                    if (onRefresh != null) SwingUtilities.invokeLater(onRefresh);
                }
            }
        });

        JButton openBtn = new JButton("Open Session");
        openBtn.addActionListener(e -> {
            if (dirty.get() && activeSessionFile != null) {
                int res = JOptionPane.showConfirmDialog(parent, "Save current session before opening another?", "Unsaved Changes", JOptionPane.YES_NO_CANCEL_OPTION);
                if (res == JOptionPane.YES_OPTION) saveNow();
                else if (res == JOptionPane.CANCEL_OPTION) return;
            }
            JFileChooser chooser = new JFileChooser(getLastDirectory());
            chooser.setDialogTitle("Select Header Inspector Session File to Open");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                File sel = chooser.getSelectedFile();
                rememberDirectory(sel.getParent());
                openSessionFile(sel);
                if (onRefresh != null) SwingUtilities.invokeLater(onRefresh);
            }
        });

        JButton offboardBtn = new JButton("Offboard Session");
        offboardBtn.addActionListener(e -> offboardSession(parent, onRefresh));

        JButton saveAsBtn = new JButton("Save As...");
        saveAsBtn.addActionListener(e -> saveAs(parent));

        JButton saveNowBtn = new JButton("Save Now");
        saveNowBtn.addActionListener(e -> {
            if (activeSessionFile == null) {
                saveAs(parent);
            } else {
                saveNow();
                JOptionPane.showMessageDialog(parent, "Session saved successfully.", "Session Saved", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        bar.add(sessionStatusLabel);
        bar.add(newBtn);
        bar.add(openBtn);
        bar.add(offboardBtn);
        bar.add(saveAsBtn);
        bar.add(saveNowBtn);
        return bar;
    }

    private HttpRequest reconstructRequest(boolean hasRequest, String reqBase64, String host, int port, boolean secure) {
        if (!hasRequest || reqBase64 == null || reqBase64.isEmpty()) return null;
        try {
            byte[] bytes = Base64.getDecoder().decode(reqBase64);
            HttpService svc = (host != null && !host.isBlank())
                    ? HttpService.httpService(host, port > 0 ? port : (secure ? 443 : 80), secure)
                    : null;
            ByteArray ba = ByteArray.byteArray(bytes);
            return (svc != null) ? HttpRequest.httpRequest(svc, ba) : HttpRequest.httpRequest(ba);
        } catch (Exception ignored) {
            return null;
        }
    }

    private HttpResponse reconstructResponse(boolean hasResponse, String respBase64) {
        if (!hasResponse || respBase64 == null || respBase64.isEmpty()) return null;
        try {
            byte[] bytes = Base64.getDecoder().decode(respBase64);
            return HttpResponse.httpResponse(ByteArray.byteArray(bytes));
        } catch (Exception ignored) {
            return null;
        }
    }

    private ZonedDateTime parseTimestamp(String ts) {
        if (ts != null && !ts.isBlank()) {
            try {
                return ZonedDateTime.parse(ts);
            } catch (Exception ignored) {}
        }
        return ZonedDateTime.now();
    }

    private File getLastDirectory() {
        String lastDir = null;
        if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
            try {
                lastDir = api.persistence().preferences().getString(SessionStartupDialog_littlespidy.PREF_GLOBAL_LAST_SESSION_DIR);
                if (lastDir == null || lastDir.isBlank()) {
                    lastDir = api.persistence().preferences().getString(SessionStartupDialog_littlespidy.PREF_LAST_SESSION_DIR);
                }
            } catch (Exception ignored) {}
        }
        if (lastDir != null && !lastDir.isBlank()) {
            File d = new File(lastDir);
            if (d.exists()) return d;
        }
        return new File(System.getProperty("user.home", "."));
    }

    private void rememberDirectory(String dirPath) {
        if (api != null && api.persistence() != null && api.persistence().preferences() != null && dirPath != null) {
            try {
                api.persistence().preferences().setString(SessionStartupDialog_littlespidy.PREF_GLOBAL_LAST_SESSION_DIR, dirPath);
                api.persistence().preferences().setString(SessionStartupDialog_littlespidy.PREF_LAST_SESSION_DIR, dirPath);
            } catch (Exception ignored) {}
        }
    }

    private void updateStatusLabel() {
        SwingUtilities.invokeLater(() -> {
            if (activeSessionFile != null) {
                sessionStatusLabel.setText("Session: " + activeSessionFile.getName() + " (" + activeSessionFile.getParent() + ")");
                sessionStatusLabel.setToolTipText(activeSessionFile.getAbsolutePath());
            } else {
                sessionStatusLabel.setText("Session: [Temporary / In-Memory]");
                sessionStatusLabel.setToolTipText("Data is currently in-memory. Use 'Save As...' to bind to a file.");
            }
        });
    }

    public void shutdown() {
        if (activeSessionFile != null && dirty.get()) {
            saveNow();
        }
        autoSaveExecutor.shutdownNow();
    }

    public File getActiveSessionFile() { return activeSessionFile; }
    public boolean isDirty() { return dirty.get(); }

    private void log(String msg) {
        if (api != null && api.logging() != null) api.logging().logToOutput(msg);
    }

    private void logError(String msg) {
        if (api != null && api.logging() != null) api.logging().logToError(msg);
    }
}
