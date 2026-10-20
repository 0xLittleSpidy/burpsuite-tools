// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.activescansessionkeeper.config.CookieMode;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.model.ScanActivityDataStore;
import com.littlespidy.activescansessionkeeper.model.ScanActivityEntry;
import com.littlespidy.activescansessionkeeper.storage.SessionKeeperSessionDTO_littlespidy.*;
import com.littlespidy.activescansessionkeeper.ui.ActiveScanSessionKeeperTab;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for Active Scan Session Keeper.
 * Plain ASCII text only.
 */
public class ActiveScanSessionKeeperPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ActiveScanKeeper-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);

    private ActiveScanSessionKeeperTab boundTab;
    private SessionKeeperConfig boundConfig;
    private ScanActivityDataStore boundDataStore;

    private final JLabel sessionStatusLabel;

    public ActiveScanSessionKeeperPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        this.autoSaveExecutor.scheduleWithFixedDelay(this::autoSaveIfDirty, 30, 30, TimeUnit.SECONDS);
    }

    public void bindContext(ActiveScanSessionKeeperTab tab, SessionKeeperConfig config, ScanActivityDataStore dataStore) {
        this.boundTab = tab;
        this.boundConfig = config;
        this.boundDataStore = dataStore;

        if (this.boundConfig != null) {
            this.boundConfig.addChangeListener(this::markDirty);
        }
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

    public synchronized void openSessionFile(File file) {
        if (file == null || !file.exists()) return;
        try {
            String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            SessionRootDTO root = gson.fromJson(json, SessionRootDTO.class);
            if (root == null) {
                throw new IllegalStateException("Corrupted or empty session JSON file.");
            }

            restoreFromDTO(root);

            this.activeSessionFile = file;
            this.dirty.set(false);
            updateStatusLabel("Session: " + file.getName() + " (Auto-save Enabled)");
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("Successfully loaded session from: " + file.getAbsolutePath());
            }
        } catch (Exception e) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("Error loading session from " + file.getAbsolutePath() + ": " + e.getMessage());
            }
            JOptionPane.showMessageDialog(boundTab,
                    "Failed to load session: " + e.getMessage(),
                    "Session Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public synchronized void createNewSessionFile(File file) {
        if (file == null) return;
        try {
            this.activeSessionFile = file;
            saveSessionToFile(file);
            this.dirty.set(false);
            updateStatusLabel("Session: " + file.getName() + " (Auto-save Enabled)");
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("Created new session file: " + file.getAbsolutePath());
            }
        } catch (Exception e) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("Error creating new session file " + file.getAbsolutePath() + ": " + e.getMessage());
            }
        }
    }

    public synchronized void startTemporarySession() {
        this.activeSessionFile = null;
        this.dirty.set(false);
        updateStatusLabel("Session: [In-Memory / Temporary]");
    }

    public synchronized void saveActiveSession() {
        if (activeSessionFile != null) {
            saveSessionToFile(activeSessionFile);
            this.dirty.set(false);
        } else {
            saveAsSession(boundTab);
        }
    }

    public synchronized void saveAsSession(Component parent) {
        File lastDir = getLastDirectory();
        JFileChooser chooser = new JFileChooser(lastDir);
        chooser.setDialogTitle("Save Active Scan Session As...");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        chooser.setSelectedFile(new File(lastDir, "activescan_session_keeper_session.json"));

        int res = chooser.showSaveDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            rememberDirectory(sel.getParent());
            this.activeSessionFile = sel;
            saveSessionToFile(sel);
            this.dirty.set(false);
            updateStatusLabel("Session: " + sel.getName() + " (Auto-save Enabled)");
        }
    }

    public synchronized void loadSessionPrompt(Component parent) {
        File lastDir = getLastDirectory();
        JFileChooser chooser = new JFileChooser(lastDir);
        chooser.setDialogTitle("Load Active Scan Session...");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));

        int res = chooser.showOpenDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            rememberDirectory(sel.getParent());
            openSessionFile(sel);
        }
    }

    public synchronized void offboardSession(Component parent) {
        int confirm = JOptionPane.showConfirmDialog(
                parent,
                "Offboarding will unbind the active session file and clear scan activities.\n" +
                        "Do you wish to proceed?",
                "Offboard Session",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );
        if (confirm == JOptionPane.YES_OPTION) {
            if (activeSessionFile != null && dirty.get()) {
                saveSessionToFile(activeSessionFile);
            }
            this.activeSessionFile = null;
            this.dirty.set(false);

            if (boundDataStore != null) {
                boundDataStore.clear();
            }
            if (boundConfig != null) {
                boundConfig.setCookieValue("");
                boundConfig.setFullCookieHeader("");
                boundConfig.setAuthBearerToken("");
                boundConfig.setTargetHostFilter("*");
                boundConfig.notifyChanged();
            }
            if (boundTab != null) {
                boundTab.refreshUI();
            }

            updateStatusLabel("Session: [Fresh / Unbound]");
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("Active Scan Session Keeper session offboarded.");
            }
        }
    }

    public void markDirty() {
        this.dirty.set(true);
    }

    public synchronized SessionRootDTO exportSessionDTO() {
        SessionRootDTO root = new SessionRootDTO();
        root.savedAt = Instant.now().toString();

        if (boundConfig != null) {
            root.enabled = boundConfig.isEnabled();
            root.monitorScanner = boundConfig.isMonitorScanner();
            root.monitorRepeater = boundConfig.isMonitorRepeater();
            root.monitorIntruder = boundConfig.isMonitorIntruder();
            root.monitorExtensions = boundConfig.isMonitorExtensions();
            root.inScopeOnly = boundConfig.isInScopeOnly();
            root.targetHostFilter = boundConfig.getTargetHostFilter();

            root.cookieMode = boundConfig.getCookieMode() != null ? boundConfig.getCookieMode().name() : "FULL_COOKIE_HEADER";
            root.targetCookieNames = boundConfig.getTargetCookieNames();
            root.cookieValue = boundConfig.getCookieValue();
            root.fullCookieHeader = boundConfig.getFullCookieHeader();
            root.updateAuthBearer = boundConfig.isUpdateAuthBearer();
            root.authBearerToken = boundConfig.getAuthBearerToken();

            root.autoRetryOnExpire = boundConfig.isAutoRetryOnExpire();
            root.soundAlertOnExpire = boundConfig.isSoundAlertOnExpire();

            root.checkStatusCodes = boundConfig.isCheckStatusCodes();
            root.statusCodes = boundConfig.getStatusCodes();
            root.checkRedirects = boundConfig.isCheckRedirects();
            root.redirectLocationRegex = boundConfig.getRedirectLocationRegex();
            root.checkBodyKeywords = boundConfig.isCheckBodyKeywords();
            root.bodyKeywords = boundConfig.getBodyKeywords();
            root.checkSetCookieInvalidation = boundConfig.isCheckSetCookieInvalidation();
            root.checkBodyLengthDrop = boundConfig.isCheckBodyLengthDrop();
            root.bodyLengthDropThreshold = boundConfig.getBodyLengthDropThreshold();
            root.checkCustomRegex = boundConfig.isCheckCustomRegex();
            root.customRegexPattern = boundConfig.getCustomRegexPattern();
        }

        if (boundDataStore != null) {
            for (ScanActivityEntry entry : boundDataStore.getEntries()) {
                ScanActivityEntryDTO edto = new ScanActivityEntryDTO();
                edto.id = entry.getId();
                edto.timestamp = entry.getTimestamp();
                edto.tool = entry.getTool();
                edto.method = entry.getMethod();
                edto.host = entry.getHost();
                edto.url = entry.getUrl();
                edto.statusCode = entry.getStatusCode();
                edto.eventType = entry.getEventType();
                edto.details = entry.getDetails();

                if (entry.getRequestResponse() != null) {
                    edto.hasRequestResponse = true;
                    if (entry.getRequestResponse().request() != null) {
                        try {
                            edto.requestBase64 = Base64.getEncoder().encodeToString(entry.getRequestResponse().request().toByteArray().getBytes());
                            if (entry.getRequestResponse().request().httpService() != null) {
                                edto.reqHost = entry.getRequestResponse().request().httpService().host();
                                edto.reqPort = entry.getRequestResponse().request().httpService().port();
                                edto.reqSecure = entry.getRequestResponse().request().httpService().secure();
                            }
                        } catch (Exception ignored) {}
                    }
                    if (entry.getRequestResponse().response() != null) {
                        try {
                            edto.responseBase64 = Base64.getEncoder().encodeToString(entry.getRequestResponse().response().toByteArray().getBytes());
                        } catch (Exception ignored) {}
                    }
                }
                root.logEntries.add(edto);
            }
        }

        return root;
    }

    public synchronized void restoreFromDTO(SessionRootDTO root) {
        if (root == null) return;

        if (boundConfig != null) {
            boundConfig.setEnabled(root.enabled);
            boundConfig.setMonitorScanner(root.monitorScanner);
            boundConfig.setMonitorRepeater(root.monitorRepeater);
            boundConfig.setMonitorIntruder(root.monitorIntruder);
            boundConfig.setMonitorExtensions(root.monitorExtensions);
            boundConfig.setInScopeOnly(root.inScopeOnly);
            boundConfig.setTargetHostFilter(root.targetHostFilter);

            try {
                if (root.cookieMode != null) {
                    boundConfig.setCookieMode(CookieMode.valueOf(root.cookieMode));
                }
            } catch (Exception ignored) {}

            boundConfig.setTargetCookieNames(root.targetCookieNames);
            boundConfig.setCookieValue(root.cookieValue);
            boundConfig.setFullCookieHeader(root.fullCookieHeader);
            boundConfig.setUpdateAuthBearer(root.updateAuthBearer);
            boundConfig.setAuthBearerToken(root.authBearerToken);

            boundConfig.setAutoRetryOnExpire(root.autoRetryOnExpire);
            boundConfig.setSoundAlertOnExpire(root.soundAlertOnExpire);

            boundConfig.setCheckStatusCodes(root.checkStatusCodes);
            boundConfig.setStatusCodes(root.statusCodes);
            boundConfig.setCheckRedirects(root.checkRedirects);
            boundConfig.setRedirectLocationRegex(root.redirectLocationRegex);
            boundConfig.setCheckBodyKeywords(root.checkBodyKeywords);
            boundConfig.setBodyKeywords(root.bodyKeywords);
            boundConfig.setCheckSetCookieInvalidation(root.checkSetCookieInvalidation);
            boundConfig.setCheckBodyLengthDrop(root.checkBodyLengthDrop);
            boundConfig.setBodyLengthDropThreshold(root.bodyLengthDropThreshold);
            boundConfig.setCheckCustomRegex(root.checkCustomRegex);
            boundConfig.setCustomRegexPattern(root.customRegexPattern);

            boundConfig.notifyChanged();
        }

        if (boundDataStore != null && root.logEntries != null) {
            List<ScanActivityEntry> restoredList = new ArrayList<>();
            for (ScanActivityEntryDTO edto : root.logEntries) {
                HttpRequestResponse rr = null;
                if (edto.hasRequestResponse) {
                    HttpRequest req = null;
                    HttpResponse resp = null;
                    if (edto.requestBase64 != null) {
                        byte[] reqBytes = Base64.getDecoder().decode(edto.requestBase64);
                        req = createRequest(reqBytes, edto.reqHost, edto.reqPort, edto.reqSecure);
                    }
                    if (edto.responseBase64 != null) {
                        byte[] respBytes = Base64.getDecoder().decode(edto.responseBase64);
                        resp = createResponse(respBytes);
                    }
                    if (req != null) {
                        rr = createHttpRequestResponse(req, resp);
                    }
                }

                ScanActivityEntry entry = new ScanActivityEntry(
                        edto.id,
                        edto.tool,
                        edto.method,
                        edto.host,
                        edto.url,
                        edto.statusCode,
                        edto.eventType,
                        edto.details,
                        rr
                );
                restoredList.add(entry);
            }
            boundDataStore.setEntries(restoredList);
        }

        if (boundTab != null) {
            boundTab.refreshUI();
        }
    }

    private ByteArray createByteArray(byte[] bytes) {
        try {
            return ByteArray.byteArray(bytes);
        } catch (Throwable t) {
            byte[] safeBytes = (bytes != null) ? bytes : new byte[0];
            return (ByteArray) java.lang.reflect.Proxy.newProxyInstance(
                    ByteArray.class.getClassLoader(),
                    new Class<?>[]{ByteArray.class},
                    (proxy, m, args) -> {
                        if ("getBytes".equals(m.getName())) return safeBytes;
                        if ("length".equals(m.getName())) return safeBytes.length;
                        return null;
                    }
            );
        }
    }

    private HttpRequest createRequest(byte[] bytes, String host, int port, boolean secure) {
        try {
            if (host != null && !host.isEmpty()) {
                HttpService service = HttpService.httpService(host, port, secure);
                return HttpRequest.httpRequest(service, createByteArray(bytes));
            } else {
                return HttpRequest.httpRequest(createByteArray(bytes));
            }
        } catch (Throwable t) {
            return (HttpRequest) java.lang.reflect.Proxy.newProxyInstance(
                    HttpRequest.class.getClassLoader(),
                    new Class<?>[]{HttpRequest.class},
                    (proxy, m, args) -> {
                        if ("method".equals(m.getName())) return "POST";
                        if ("path".equals(m.getName())) return "/";
                        if ("toByteArray".equals(m.getName())) return createByteArray(bytes);
                        if ("bodyToString".equals(m.getName())) return bytes != null ? new String(bytes) : "";
                        return null;
                    }
            );
        }
    }

    private HttpResponse createResponse(byte[] bytes) {
        try {
            return HttpResponse.httpResponse(createByteArray(bytes));
        } catch (Throwable t) {
            return (HttpResponse) java.lang.reflect.Proxy.newProxyInstance(
                    HttpResponse.class.getClassLoader(),
                    new Class<?>[]{HttpResponse.class},
                    (proxy, m, args) -> {
                        if ("statusCode".equals(m.getName())) return (short) 200;
                        if ("toByteArray".equals(m.getName())) return createByteArray(bytes);
                        return null;
                    }
            );
        }
    }

    private HttpRequestResponse createHttpRequestResponse(HttpRequest req, HttpResponse resp) {
        try {
            return HttpRequestResponse.httpRequestResponse(req, resp);
        } catch (Throwable t) {
            return (HttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                    HttpRequestResponse.class.getClassLoader(),
                    new Class<?>[]{HttpRequestResponse.class},
                    (proxy, m, args) -> {
                        if ("request".equals(m.getName())) return req;
                        if ("response".equals(m.getName())) return resp;
                        if ("hasResponse".equals(m.getName())) return resp != null;
                        return null;
                    }
            );
        }
    }

    public synchronized void saveSessionToFile(File targetFile) {
        if (targetFile == null) return;
        try {
            SessionRootDTO root = exportSessionDTO();
            String json = gson.toJson(root);

            File parentDir = targetFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            File tempFile = new File(targetFile.getAbsolutePath() + ".tmp");
            Files.writeString(tempFile.toPath(), json, StandardCharsets.UTF_8);
            Files.move(tempFile.toPath(), targetFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);

            if (api != null && api.logging() != null) {
                api.logging().logToOutput("Active Scan Session Keeper session saved successfully to: " + targetFile.getName());
            }
        } catch (Exception e) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("Failed to save session to " + targetFile.getAbsolutePath() + ": " + e.getMessage());
            }
        }
    }

    private void autoSaveIfDirty() {
        if (dirty.get() && activeSessionFile != null) {
            try {
                saveSessionToFile(activeSessionFile);
                dirty.set(false);
            } catch (Exception ignored) {}
        }
    }

    public JPanel createSessionToolbar() {
        JPanel bar = new JPanel(new BorderLayout(8, 0));
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton saveBtn = new JButton("Save Session");
        saveBtn.setToolTipText("Save current session state to the active file");
        saveBtn.addActionListener(e -> saveActiveSession());

        JButton saveAsBtn = new JButton("Save As...");
        saveAsBtn.setToolTipText("Save current session to a new file");
        saveAsBtn.addActionListener(e -> saveAsSession(bar));

        JButton loadBtn = new JButton("Load Session...");
        loadBtn.setToolTipText("Load a previously saved session file");
        loadBtn.addActionListener(e -> loadSessionPrompt(bar));

        JButton offboardBtn = new JButton("Offboard Session");
        offboardBtn.setToolTipText("Reset configurations and unbind the active session file");
        offboardBtn.addActionListener(e -> offboardSession(bar));

        leftPanel.add(saveBtn);
        leftPanel.add(saveAsBtn);
        leftPanel.add(loadBtn);
        leftPanel.add(offboardBtn);

        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        rightPanel.add(sessionStatusLabel);

        bar.add(leftPanel, BorderLayout.WEST);
        bar.add(rightPanel, BorderLayout.EAST);

        return bar;
    }

    private void updateStatusLabel(String text) {
        SwingUtilities.invokeLater(() -> sessionStatusLabel.setText(text));
    }

    private File getLastDirectory() {
        String lastDir = null;
        if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
            try {
                lastDir = api.persistence().preferences().getString(SessionStartupDialog_littlespidy.PREF_GLOBAL_LAST_SESSION_DIR);
                if (lastDir == null || lastDir.isBlank()) {
                    lastDir = api.persistence().preferences().getString("burp_extensions_last_session_dir_littlespidy");
                }
                if (lastDir == null || lastDir.isBlank()) {
                    lastDir = api.persistence().preferences().getString(SessionStartupDialog_littlespidy.PREF_LAST_SESSION_DIR);
                }
            } catch (Exception ignored) {}
        }
        if (lastDir != null && !lastDir.isBlank()) {
            File d = new File(lastDir);
            if (d.exists() && d.isDirectory()) return d;
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

    public void shutdown() {
        if (activeSessionFile != null && dirty.get()) {
            saveSessionToFile(activeSessionFile);
        }
        autoSaveExecutor.shutdown();
        try {
            if (!autoSaveExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                autoSaveExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            autoSaveExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public File getActiveSessionFile() {
        return activeSessionFile;
    }
}
