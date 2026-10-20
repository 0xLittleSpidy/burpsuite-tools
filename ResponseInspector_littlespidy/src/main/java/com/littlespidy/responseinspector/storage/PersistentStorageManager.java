// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.responseinspector.engine.PasswordScanner;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InScopeDomainManager;
import com.littlespidy.responseinspector.model.InspectorDataStore;
import com.littlespidy.responseinspector.model.SecretClassification;
import com.littlespidy.responseinspector.model.SecretClassificationManager;
import com.littlespidy.responseinspector.storage.SessionStateDTO_littlespidy.*;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent session storage, state recovery, and session offboarding
 * for Response Inspector across extension reloads and Burp Suite restarts.
 *
 * Adheres strictly to the Extension Architecture standard:
 * 1. Never loads a previous session by default.
 * 2. Prompts user on load (Open Previous vs Create New with directory vs Temporary).
 * 3. Provides clean session offboarding to restore fresh extension state at any time.
 * 4. High-fidelity JSON persistence with Base64 HTTP message preservation.
 * 5. Debounced atomic auto-save engine.
 */
public class PersistentStorageManager {

    public static final String PREF_STORAGE_DIR = "response_inspector_storage_dir";
    public static final String DEFAULT_SESSION_FILENAME = "response_inspector_session.json";

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ResponseInspector-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private ScheduledFuture<?> scheduledSaveTask = null;
    private ResponseScanEngine boundScanEngine = null;
    private InScopeDomainManager boundDomainManager = null;

    private final JLabel sessionStatusLabel;

    public PersistentStorageManager(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    }

    public void bindEngines(ResponseScanEngine scanEngine, InScopeDomainManager domainManager) {
        this.boundScanEngine = scanEngine;
        this.boundDomainManager = domainManager;
    }

    /**
     * Initializes session on extension load by presenting the interactive startup modal dialog.
     * Strictly avoids loading any session by default.
     */
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

            // 1. Reset current state
            resetCurrentState();

            // 2. Restore passwords
            if (boundScanEngine != null && boundScanEngine.getPasswordScanner() != null && root.passwordsConfig != null) {
                PasswordScanner ps = boundScanEngine.getPasswordScanner();
                ps.setCaseSensitive(root.passwordsConfig.caseSensitive);
                if (root.passwordsConfig.passwords != null) {
                    for (String pw : root.passwordsConfig.passwords) {
                        ps.addPassword(pw);
                    }
                }
            }

            // 3. Restore in-scope domains
            if (boundDomainManager != null && root.inScopeDomains != null) {
                List<String> selectedDomains = new ArrayList<>();
                for (DomainEntryDTO d : root.inScopeDomains) {
                    if (d.domain != null && !d.domain.isBlank()) {
                        boundDomainManager.addDomain(d.domain);
                        if (d.selected) {
                            selectedDomains.add(d.domain);
                        }
                        for (int i = 0; i < d.findingCount; i++) {
                            boundDomainManager.registerFinding(d.domain);
                        }
                    }
                }
                if (!selectedDomains.isEmpty()) {
                    boundDomainManager.setSelectedDomains(selectedDomains);
                }
            }

            // 4. Restore secret type classifications
            SecretClassificationManager scm = (boundScanEngine != null) ? boundScanEngine.getSecretClassificationManager() : null;
            if (scm != null && root.secretTypeClassifications != null) {
                for (Map.Entry<String, String> entry : root.secretTypeClassifications.entrySet()) {
                    try {
                        scm.markSecretType(entry.getKey(), SecretClassification.valueOf(entry.getValue()));
                    } catch (Exception ignored) {}
                }
            }

            // 5. Restore findings
            int restoredCount = 0;
            if (root.findings != null) {
                for (FindingEntryDTO dto : root.findings) {
                    FindingCategory category;
                    try {
                        category = FindingCategory.valueOf(dto.category);
                    } catch (Exception e) {
                        category = FindingCategory.SECRET;
                    }

                    HttpRequest req = null;
                    if (dto.hasRequest && dto.requestBase64 != null && !dto.requestBase64.isEmpty()) {
                        try {
                            byte[] reqBytes = Base64.getDecoder().decode(dto.requestBase64);
                            HttpService svc = (dto.requestHost != null && !dto.requestHost.isBlank())
                                    ? HttpService.httpService(dto.requestHost, dto.requestPort > 0 ? dto.requestPort : (dto.requestSecure ? 443 : 80), dto.requestSecure)
                                    : null;
                            ByteArray ba = ByteArray.byteArray(reqBytes);
                            req = (svc != null) ? HttpRequest.httpRequest(svc, ba) : HttpRequest.httpRequest(ba);
                        } catch (Exception ignored) {}
                    }

                    HttpResponse resp = null;
                    if (dto.hasResponse && dto.responseBase64 != null && !dto.responseBase64.isEmpty()) {
                        try {
                            byte[] respBytes = Base64.getDecoder().decode(dto.responseBase64);
                            resp = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
                        } catch (Exception ignored) {}
                    }

                    HttpRequestResponse reqResp = null;
                    if (req != null || resp != null) {
                        reqResp = HttpRequestResponse.httpRequestResponse(
                                req != null ? req : HttpRequest.httpRequest(),
                                resp != null ? resp : HttpResponse.httpResponse()
                        );
                    }

                    FindingEntry entry = new FindingEntry(
                            dto.id,
                            category,
                            dto.patternName,
                            dto.matchValue,
                            dto.matchLocation,
                            dto.method,
                            dto.url,
                            dto.host,
                            dto.path,
                            dto.statusCode,
                            dto.contentType,
                            dto.contentLength,
                            reqResp,
                            dto.timeString,
                            dto.startOffset,
                            dto.endOffset
                    );

                    if (boundScanEngine != null) {
                        InspectorDataStore ds = boundScanEngine.getDataStore(category);
                        if (ds != null && ds.addEntry(entry)) {
                            restoredCount++;
                        }
                    }

                    if (scm != null && dto.individualClassification != null && !dto.individualClassification.isBlank()) {
                        try {
                            scm.markRequest(entry, SecretClassification.valueOf(dto.individualClassification));
                        } catch (Exception ignored) {}
                    }
                }
            }

            this.activeSessionFile = file;
            this.dirty.set(false);
            updateStatusLabel();
            log("[Response Inspector] Session opened successfully from: " + file.getAbsolutePath() + " (Restored " + restoredCount + " findings)");
        } catch (Exception ex) {
            logError("[Response Inspector] Failed to open session from " + file.getAbsolutePath() + ": " + ex.getMessage());
            JOptionPane.showMessageDialog(null, "Failed to load session file:\n" + ex.getMessage(), "Session Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public synchronized void createNewSessionFile(File file) {
        if (file == null) return;
        resetCurrentState();
        this.activeSessionFile = file;
        this.dirty.set(true);
        saveNow();
        updateStatusLabel();
        log("[Response Inspector] Created new session bound to: " + file.getAbsolutePath());
    }

    public synchronized void startTemporarySession() {
        resetCurrentState();
        this.activeSessionFile = null;
        this.dirty.set(false);
        updateStatusLabel();
        log("[Response Inspector] Started temporary in-memory session.");
    }

    /**
     * Offboards the currently active session file, restoring the extension to a fresh state.
     */
    public synchronized void offboardSession(Component parent, Runnable onRefresh) {
        if (activeSessionFile != null && dirty.get()) {
            int choice = JOptionPane.showConfirmDialog(
                    parent,
                    "Save changes to '" + activeSessionFile.getName() + "' before offboarding?",
                    "Offboard Session - Unsaved Changes",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (choice == JOptionPane.YES_OPTION) {
                saveNow();
            } else if (choice == JOptionPane.CANCEL_OPTION) {
                return;
            }
        }

        if (scheduledSaveTask != null && !scheduledSaveTask.isDone()) {
            scheduledSaveTask.cancel(false);
        }

        resetCurrentState();
        File previousFile = this.activeSessionFile;
        this.activeSessionFile = null;
        this.dirty.set(false);
        updateStatusLabel();

        log("[Response Inspector] Offboarded session " + (previousFile != null ? previousFile.getName() : "") + ". Restored clean fresh extension state.");
        if (onRefresh != null) {
            SwingUtilities.invokeLater(onRefresh);
        }
    }

    public synchronized boolean saveNow() {
        if (activeSessionFile == null) {
            return false;
        }

        try {
            SessionRootDTO root = new SessionRootDTO();
            root.formatVersion = 1;
            root.savedAt = Instant.now().toString();
            root.sessionName = activeSessionFile.getName();

            // Passwords
            if (boundScanEngine != null && boundScanEngine.getPasswordScanner() != null) {
                PasswordScanner ps = boundScanEngine.getPasswordScanner();
                root.passwordsConfig.caseSensitive = ps.isCaseSensitive();
                root.passwordsConfig.passwords = new ArrayList<>(ps.getPasswords());
            }

            // In-scope domains
            if (boundDomainManager != null) {
                for (String dom : boundDomainManager.getAllDomains()) {
                    root.inScopeDomains.add(new DomainEntryDTO(
                            dom,
                            boundDomainManager.isDomainSelected(dom),
                            boundDomainManager.getFindingCount(dom)
                    ));
                }
            }

            // Secret classifications
            SecretClassificationManager scm = (boundScanEngine != null) ? boundScanEngine.getSecretClassificationManager() : null;
            if (scm != null && boundScanEngine.getSecretScanner() != null) {
                for (String rule : boundScanEngine.getSecretScanner().getRuleNames()) {
                    SecretClassification cl = scm.getTypeClassification(rule);
                    if (cl != SecretClassification.NOT_VERIFIED) {
                        root.secretTypeClassifications.put(rule, cl.name());
                    }
                }
            }

            // Findings
            if (boundScanEngine != null) {
                for (FindingCategory cat : FindingCategory.values()) {
                    InspectorDataStore ds = boundScanEngine.getDataStore(cat);
                    if (ds != null) {
                        for (FindingEntry e : ds.getAllEntries()) {
                            FindingEntryDTO dto = new FindingEntryDTO();
                            dto.id = e.id();
                            dto.category = e.category().name();
                            dto.patternName = e.patternName();
                            dto.matchValue = e.matchValue();
                            dto.matchLocation = e.matchLocation();
                            dto.method = e.method();
                            dto.url = e.url();
                            dto.host = e.host();
                            dto.path = e.path();
                            dto.statusCode = e.statusCode();
                            dto.contentType = e.contentType();
                            dto.contentLength = e.contentLength();
                            dto.timeString = e.timeString();
                            dto.startOffset = e.startOffset();
                            dto.endOffset = e.endOffset();

                            HttpRequestResponse reqResp = e.requestResponse();
                            if (reqResp != null) {
                                if (reqResp.request() != null) {
                                    HttpRequest req = reqResp.request();
                                    dto.hasRequest = true;
                                    HttpService svc = req.httpService();
                                    dto.requestHost = (svc != null) ? svc.host() : "";
                                    dto.requestPort = (svc != null) ? svc.port() : 0;
                                    dto.requestSecure = (svc != null) && svc.secure();
                                    dto.requestBase64 = Base64.getEncoder().encodeToString(req.toByteArray().getBytes());
                                }
                                if (reqResp.hasResponse() && reqResp.response() != null) {
                                    dto.hasResponse = true;
                                    dto.responseBase64 = Base64.getEncoder().encodeToString(reqResp.response().toByteArray().getBytes());
                                }
                            }

                            if (scm != null && scm.hasIndividualClassification(e)) {
                                SecretClassification indCl = scm.getIndividualClassification(e);
                                if (indCl != null) {
                                    dto.individualClassification = indCl.name();
                                }
                            }

                            root.findings.add(dto);
                        }
                    }
                }
            }

            String json = gson.toJson(root);
            File parentDir = activeSessionFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            File tmpFile = new File(activeSessionFile.getAbsolutePath() + ".tmp");
            Files.writeString(tmpFile.toPath(), json, StandardCharsets.UTF_8);

            try {
                Files.move(tmpFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.move(tmpFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }

            dirty.set(false);
            updateStatusLabel();
            return true;
        } catch (Exception ex) {
            logError("[Response Inspector] Failed to save session to " + activeSessionFile.getAbsolutePath() + ": " + ex.getMessage());
            return false;
        }
    }

    public synchronized void scheduleAutoSave() {
        dirty.set(true);
        if (activeSessionFile == null) {
            return;
        }
        if (scheduledSaveTask != null && !scheduledSaveTask.isDone()) {
            scheduledSaveTask.cancel(false);
        }
        scheduledSaveTask = autoSaveExecutor.schedule(this::saveNow, 1500, TimeUnit.MILLISECONDS);
    }

    public synchronized void saveAs(File file) {
        if (file == null) return;
        this.activeSessionFile = file;
        this.dirty.set(true);
        saveNow();
        updateStatusLabel();
    }

    public JPanel createSessionToolbarComponent(Component parent, Runnable onRefresh, Runnable onAnalyzeFile) {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JButton newBtn = new JButton("New Session");
        newBtn.setToolTipText("Create a new session file in a user-specified directory");
        newBtn.addActionListener(e -> {
            if (dirty.get() && activeSessionFile != null) {
                int res = JOptionPane.showConfirmDialog(parent, "Save current session before creating a new one?", "Unsaved Changes", JOptionPane.YES_NO_CANCEL_OPTION);
                if (res == JOptionPane.YES_OPTION) saveNow();
                else if (res == JOptionPane.CANCEL_OPTION) return;
            }

            JFileChooser dirChooser = new JFileChooser(getLastDirectory());
            dirChooser.setDialogTitle("Select Directory For New Session");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (dirChooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File dir = dirChooser.getSelectedFile();
                rememberDirectory(dir.getAbsolutePath());
                String name = JOptionPane.showInputDialog(parent, "Enter session filename:", DEFAULT_SESSION_FILENAME);
                if (name != null && !name.isBlank()) {
                    String clean = name.trim();
                    if (!clean.toLowerCase().endsWith(".json")) clean += ".json";
                    createNewSessionFile(new File(dir, clean));
                    if (onRefresh != null) onRefresh.run();
                }
            }
        });

        JButton openBtn = new JButton("Open Session");
        openBtn.setToolTipText("Open an existing Response Inspector session JSON file");
        openBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(getLastDirectory());
            chooser.setDialogTitle("Select Session File to Open");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File sel = chooser.getSelectedFile();
                rememberDirectory(sel.getParent());
                openSessionFile(sel);
                if (onRefresh != null) onRefresh.run();
            }
        });

        JButton offboardBtn = new JButton("Offboard Session");
        offboardBtn.setToolTipText("Unbind active session file and restore fresh extension state");
        offboardBtn.addActionListener(e -> offboardSession(parent, onRefresh));

        JButton saveAsBtn = new JButton("Save As...");
        saveAsBtn.setToolTipText("Save current session data to a new JSON file");
        saveAsBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(getLastDirectory());
            chooser.setDialogTitle("Save Session As");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            if (chooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File sel = chooser.getSelectedFile();
                String name = sel.getName();
                if (!name.toLowerCase().endsWith(".json")) {
                    sel = new File(sel.getParentFile(), name + ".json");
                }
                rememberDirectory(sel.getParent());
                saveAs(sel);
                if (onRefresh != null) onRefresh.run();
            }
        });

        JButton saveNowBtn = new JButton("Save Now");
        saveNowBtn.setToolTipText("Immediately write current findings to the bound session file");
        saveNowBtn.addActionListener(e -> {
            if (activeSessionFile == null) {
                saveAsBtn.doClick();
            } else {
                dirty.set(true);
                boolean ok = saveNow();
                if (ok) {
                    JOptionPane.showMessageDialog(parent, "Session saved successfully to:\n" + activeSessionFile.getAbsolutePath(), "Saved", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        JButton analyzeFileBtn = new JButton("Analyze File...");
        analyzeFileBtn.setToolTipText("Select and analyze a file from local disk with all Response Inspector scanners");
        if (onAnalyzeFile != null) {
            analyzeFileBtn.addActionListener(e -> onAnalyzeFile.run());
        }

        toolbar.add(sessionStatusLabel);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(newBtn);
        toolbar.add(openBtn);
        toolbar.add(offboardBtn);
        toolbar.add(saveAsBtn);
        toolbar.add(saveNowBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(analyzeFileBtn);

        return toolbar;
    }

    private void resetCurrentState() {
        if (boundScanEngine != null) {
            boundScanEngine.clearAll();
        }
        if (boundDomainManager != null) {
            boundDomainManager.deselectAll();
        }
    }

    private void updateStatusLabel() {
        SwingUtilities.invokeLater(() -> {
            if (activeSessionFile != null) {
                String dirtyMarker = dirty.get() ? " *" : "";
                sessionStatusLabel.setText("Session: " + activeSessionFile.getName() + dirtyMarker);
                sessionStatusLabel.setToolTipText(activeSessionFile.getAbsolutePath());
            } else {
                sessionStatusLabel.setText("Session: [Fresh / Unbound]");
                sessionStatusLabel.setToolTipText("Extension is clean and unbound. Use 'Open Session' or 'New Session' to bind.");
            }
        });
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

    public synchronized File getStorageDirectory() {
        if (activeSessionFile != null) {
            return activeSessionFile.getParentFile();
        }
        return getDefaultStorageDirectory();
    }

    public synchronized void setStorageDirectory(File newDir) {
        if (newDir == null) return;
        newDir.mkdirs();
        this.activeSessionFile = new File(newDir, DEFAULT_SESSION_FILENAME);
        rememberDirectory(newDir.getAbsolutePath());
    }

    public static File getDefaultStorageDirectory() {
        String userHome = System.getProperty("user.home", ".");
        File burpDir = new File(userHome, ".BurpSuite");
        return new File(burpDir, "response-inspector");
    }

    public boolean isTemporaryProject() {
        return activeSessionFile == null;
    }

    public void promptUserIfTemporaryProject(Window parent) {
        // Handled via initializeSessionOnStartup
    }

    public synchronized boolean saveData(ResponseScanEngine scanEngine, InScopeDomainManager domainManager) {
        if (activeSessionFile == null) {
            File defaultDir = getDefaultStorageDirectory();
            defaultDir.mkdirs();
            this.activeSessionFile = new File(defaultDir, DEFAULT_SESSION_FILENAME);
        }
        dirty.set(true);
        return saveNow();
    }

    public synchronized int loadData(ResponseScanEngine scanEngine, InScopeDomainManager domainManager) {
        if (activeSessionFile != null && activeSessionFile.exists()) {
            openSessionFile(activeSessionFile);
            int total = 0;
            if (scanEngine != null) {
                for (FindingCategory cat : FindingCategory.values()) {
                    total += scanEngine.getDataStore(cat).size();
                }
            }
            return total;
        }
        return 0;
    }

    public synchronized boolean deleteStoredData() {
        if (activeSessionFile != null && activeSessionFile.exists()) {
            boolean del = activeSessionFile.delete();
            activeSessionFile = null;
            updateStatusLabel();
            return del;
        }
        return true;
    }

    public long getStorageSizeBytes() {
        if (activeSessionFile != null && activeSessionFile.exists()) {
            return activeSessionFile.length();
        }
        return 0;
    }

    public String getLastModifiedFormatted() {
        if (activeSessionFile != null && activeSessionFile.exists()) {
            LocalDateTime dt = LocalDateTime.ofInstant(Instant.ofEpochMilli(activeSessionFile.lastModified()), ZoneId.systemDefault());
            return dt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        }
        return "Never";
    }

    public File getActiveSessionFile() {
        return activeSessionFile;
    }

    public void shutdown() {
        if (activeSessionFile != null && dirty.get()) {
            saveNow();
        }
        autoSaveExecutor.shutdown();
        try {
            if (!autoSaveExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                autoSaveExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            autoSaveExecutor.shutdownNow();
        }
    }

    private void log(String msg) {
        if (api != null && api.logging() != null) {
            api.logging().logToOutput(msg);
        }
    }

    private void logError(String msg) {
        if (api != null && api.logging() != null) {
            api.logging().logToError(msg);
        }
    }
}
