// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.engine.PasswordScanner;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InScopeDomainManager;
import com.littlespidy.responseinspector.model.InspectorDataStore;
import com.littlespidy.responseinspector.model.SecretClassification;
import com.littlespidy.responseinspector.model.SecretClassificationManager;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * Manages persistent storage of Response Inspector data so that findings,
 * in-scope domains, passwords, and secret classifications persist across
 * Burp Suite application restarts and extension reinstallation.
 *
 * Default storage directory: ~/.BurpSuite/response-inspector
 * If project is temporary or lacks permanent storage, prompts user to specify/confirm.
 * Data persists across restarts/reinstalls unless the user explicitly chooses to delete it.
 */
public class PersistentStorageManager {

    public static final String PREF_STORAGE_DIR = "response_inspector_storage_dir";
    private static final int MAGIC_HEADER = 0x52494644; // "RIFD"
    private static final int FORMAT_VERSION = 1;

    private static final String FINDINGS_FILE = "findings.dat";
    private static final String CONFIG_FILE = "config.properties";

    private final MontoyaApi api;
    private volatile File storageDirectory;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ResponseInspector-PersistentStorage");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private ScheduledFuture<?> scheduledSaveTask = null;
    private ResponseScanEngine boundScanEngine = null;
    private InScopeDomainManager boundDomainManager = null;

    public PersistentStorageManager(MontoyaApi api) {
        this.api = api;
        resolveStorageDirectory();
    }

    /**
     * Resolves storage directory from user preferences, or default directory within Burp Suite.
     */
    public synchronized void resolveStorageDirectory() {
        String savedPath = null;
        if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
            try {
                savedPath = api.persistence().preferences().getString(PREF_STORAGE_DIR);
            } catch (Throwable ignored) {}
        }

        if (savedPath != null && !savedPath.trim().isEmpty()) {
            File f = new File(savedPath.trim());
            if (f.exists() || f.mkdirs()) {
                this.storageDirectory = f;
                return;
            }
        }

        // Default: dedicated directory within Burp Suite's directory
        File defaultDir = getDefaultStorageDirectory();
        defaultDir.mkdirs();
        this.storageDirectory = defaultDir;
    }

    /**
     * Returns the dedicated storage directory within Burp Suite's directory (~/.BurpSuite/response-inspector).
     */
    public static File getDefaultStorageDirectory() {
        String userHome = System.getProperty("user.home", ".");
        File burpDir = new File(userHome, ".BurpSuite");
        return new File(burpDir, "response-inspector");
    }

    /**
     * Checks if the current Burp project is temporary or does not have a permanent disk location.
     */
    public boolean isTemporaryProject() {
        if (api == null) {
            return true;
        }
        try {
            java.lang.reflect.Method projectMethod = api.getClass().getMethod("project");
            Object projectObj = projectMethod.invoke(api);
            if (projectObj == null) {
                return true;
            }
            java.lang.reflect.Method nameMethod = projectObj.getClass().getMethod("name");
            Object nameObj = nameMethod.invoke(projectObj);
            if (nameObj == null) {
                return true;
            }
            String name = nameObj.toString();
            if (name.isBlank()
                    || name.equalsIgnoreCase("temporary")
                    || name.equalsIgnoreCase("temporary project")
                    || name.equalsIgnoreCase("untitled")) {
                return true;
            }
            File f = new File(name);
            if (!f.exists() && !name.toLowerCase().endsWith(".burp")) {
                return true;
            }
            return false;
        } catch (Throwable t) {
            return true;
        }
    }

    /**
     * If the project is temporary and storage location has not been explicitly configured yet,
     * asks the user where the data should be stored.
     */
    public void promptUserIfTemporaryProject(Window parent) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }

        boolean alreadyConfigured = false;
        if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
            try {
                String saved = api.persistence().preferences().getString(PREF_STORAGE_DIR);
                if (saved != null && !saved.isBlank()) {
                    alreadyConfigured = true;
                }
            } catch (Throwable ignored) {}
        }

        if (!alreadyConfigured && isTemporaryProject()) {
            SwingUtilities.invokeLater(() -> showTemporaryProjectConfigDialog(parent));
        }
    }

    private void showTemporaryProjectConfigDialog(Window parent) {
        JDialog dialog = new JDialog(parent, "Persistent Storage Configuration", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(12, 12));
        dialog.setSize(620, 260);
        dialog.setLocationRelativeTo(parent);

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JLabel info = new JLabel("<html><b>The current Burp project is temporary or does not have a permanent storage location.</b><br><br>"
                + "Response Inspector ensures your findings, secret classifications, and configurations are preserved "
                + "across restarts and extension reinstalls.<br><br>"
                + "Please specify or confirm the persistent storage directory:</html>");
        content.add(info, BorderLayout.NORTH);

        JPanel pathRow = new JPanel(new BorderLayout(8, 0));
        File defaultDir = getDefaultStorageDirectory();
        JTextField pathField = new JTextField(storageDirectory != null ? storageDirectory.getAbsolutePath() : defaultDir.getAbsolutePath());
        JButton browseBtn = new JButton("Browse...");
        browseBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(pathField.getText());
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setDialogTitle("Select Persistent Storage Directory");
            if (chooser.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION) {
                pathField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        pathRow.add(pathField, BorderLayout.CENTER);
        pathRow.add(browseBtn, BorderLayout.EAST);
        content.add(pathRow, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton defaultBtn = new JButton("Use Burp Suite Default");
        defaultBtn.addActionListener(e -> {
            setStorageDirectory(defaultDir);
            dialog.dispose();
        });

        JButton saveBtn = new JButton("Save Location");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> {
            String text = pathField.getText().trim();
            if (!text.isEmpty()) {
                File chosen = new File(text);
                chosen.mkdirs();
                setStorageDirectory(chosen);
            }
            dialog.dispose();
        });

        btnRow.add(defaultBtn);
        btnRow.add(saveBtn);
        content.add(btnRow, BorderLayout.SOUTH);

        dialog.setContentPane(content);
        dialog.setVisible(true);
    }

    public synchronized File getStorageDirectory() {
        if (storageDirectory == null) {
            resolveStorageDirectory();
        }
        return storageDirectory;
    }

    public synchronized void setStorageDirectory(File newDir) {
        if (newDir == null) return;
        newDir.mkdirs();
        this.storageDirectory = newDir;
        if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
            try {
                api.persistence().preferences().setString(PREF_STORAGE_DIR, newDir.getAbsolutePath());
            } catch (Throwable ignored) {}
        }
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("[Response Inspector] Persistent storage directory set to: " + newDir.getAbsolutePath());
        }
    }

    public void bindEngines(ResponseScanEngine scanEngine, InScopeDomainManager domainManager) {
        this.boundScanEngine = scanEngine;
        this.boundDomainManager = domainManager;
    }

    /**
     * Schedules a debounced asynchronous auto-save to write updated state to disk.
     */
    public synchronized void scheduleAutoSave() {
        dirty.set(true);
        if (scheduledSaveTask != null && !scheduledSaveTask.isDone()) {
            scheduledSaveTask.cancel(false);
        }
        scheduledSaveTask = autoSaveExecutor.schedule(this::saveNow, 1500, TimeUnit.MILLISECONDS);
    }

    /**
     * Immediately saves all data to disk.
     */
    public void saveNow() {
        if (boundScanEngine == null) return;
        saveData(boundScanEngine, boundDomainManager);
        dirty.set(false);
    }

    /**
     * Saves findings, domain configurations, passwords, and classifications atomically to disk.
     */
    public synchronized boolean saveData(ResponseScanEngine scanEngine, InScopeDomainManager domainManager) {
        File dir = getStorageDirectory();
        if (dir == null) return false;
        if (!dir.exists() && !dir.mkdirs()) return false;

        boolean success = true;

        // 1. Save config and metadata
        File configFile = new File(dir, CONFIG_FILE);
        File configTmp = new File(dir, CONFIG_FILE + ".tmp");
        try {
            Properties props = new Properties();
            props.setProperty("format_version", String.valueOf(FORMAT_VERSION));
            props.setProperty("saved_at", Instant.now().toString());

            if (scanEngine != null && scanEngine.getPasswordScanner() != null) {
                PasswordScanner ps = scanEngine.getPasswordScanner();
                props.setProperty("passwords_case_sensitive", String.valueOf(ps.isCaseSensitive()));
                props.setProperty("passwords_count", String.valueOf(ps.getPasswordCount()));
                List<String> pws = ps.getPasswords();
                for (int i = 0; i < pws.size(); i++) {
                    props.setProperty("password." + i, pws.get(i));
                }
            }

            if (domainManager != null) {
                Set<String> allDoms = domainManager.getAllDomains();
                props.setProperty("domains_count", String.valueOf(allDoms.size()));
                int idx = 0;
                for (String dom : allDoms) {
                    props.setProperty("domain." + idx, dom);
                    props.setProperty("domain_selected." + idx, String.valueOf(domainManager.isDomainSelected(dom)));
                    props.setProperty("domain_count." + idx, String.valueOf(domainManager.getFindingCount(dom)));
                    idx++;
                }
            }

            if (scanEngine != null && scanEngine.getSecretClassificationManager() != null) {
                SecretClassificationManager scm = scanEngine.getSecretClassificationManager();
                for (String rule : scanEngine.getSecretScanner().getRuleNames()) {
                    SecretClassification typeCl = scm.getTypeClassification(rule);
                    if (typeCl != SecretClassification.NOT_VERIFIED) {
                        props.setProperty("secret_type_class." + rule, typeCl.name());
                    }
                }
            }

            try (FileOutputStream fos = new FileOutputStream(configTmp)) {
                props.store(fos, "Response Inspector Persistent Configuration");
            }
            Files.move(configTmp.toPath(), configFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception ex) {
            success = false;
            if (api != null && api.logging() != null) {
                api.logging().logToError("[Persistent Storage] Failed to save config: " + ex.getMessage());
            }
        }

        // 2. Save findings binary
        File findingsFile = new File(dir, FINDINGS_FILE);
        File findingsTmp = new File(dir, FINDINGS_FILE + ".tmp");
        try {
            List<FindingEntry> allFindings = new ArrayList<>();
            if (scanEngine != null) {
                for (FindingCategory cat : FindingCategory.values()) {
                    InspectorDataStore ds = scanEngine.getDataStore(cat);
                    if (ds != null) {
                        allFindings.addAll(ds.getAllEntries());
                    }
                }
            }

            SecretClassificationManager scm = (scanEngine != null) ? scanEngine.getSecretClassificationManager() : null;

            try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(findingsTmp)))) {
                out.writeInt(MAGIC_HEADER);
                out.writeInt(FORMAT_VERSION);
                out.writeInt(allFindings.size());

                for (FindingEntry e : allFindings) {
                    out.writeInt(e.id());
                    writeSafeString(out, e.category().name());
                    writeSafeString(out, e.patternName());
                    writeSafeString(out, e.matchValue());
                    writeSafeString(out, e.matchLocation());
                    writeSafeString(out, e.method());
                    writeSafeString(out, e.url());
                    writeSafeString(out, e.host());
                    writeSafeString(out, e.path());
                    out.writeShort(e.statusCode());
                    writeSafeString(out, e.contentType());
                    out.writeInt(e.contentLength());
                    writeSafeString(out, e.timeString());
                    out.writeInt(e.startOffset());
                    out.writeInt(e.endOffset());

                    // Request / Response bytes
                    HttpRequestResponse reqResp = e.requestResponse();
                    boolean hasReq = reqResp != null && reqResp.request() != null;
                    out.writeBoolean(hasReq);
                    if (hasReq) {
                        HttpRequest req = reqResp.request();
                        HttpService svc = req.httpService();
                        writeSafeString(out, svc != null ? svc.host() : "");
                        out.writeInt(svc != null ? svc.port() : 0);
                        out.writeBoolean(svc != null && svc.secure());

                        byte[] reqBytes = req.toByteArray().getBytes();
                        out.writeInt(reqBytes.length);
                        out.write(reqBytes);
                    }

                    boolean hasResp = reqResp != null && reqResp.response() != null;
                    out.writeBoolean(hasResp);
                    if (hasResp) {
                        HttpResponse resp = reqResp.response();
                        byte[] respBytes = resp.toByteArray().getBytes();
                        out.writeInt(respBytes.length);
                        out.write(respBytes);
                    }

                    // Explicit individual secret classification override
                    boolean hasIndivClass = false;
                    String indivClassStr = null;
                    if (scm != null && scm.hasIndividualClassification(e)) {
                        SecretClassification cl = scm.getIndividualClassification(e);
                        if (cl != null) {
                            hasIndivClass = true;
                            indivClassStr = cl.name();
                        }
                    }
                    out.writeBoolean(hasIndivClass);
                    if (hasIndivClass) {
                        writeSafeString(out, indivClassStr);
                    }
                }
                out.flush();
            }

            Files.move(findingsTmp.toPath(), findingsFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception ex) {
            success = false;
            if (api != null && api.logging() != null) {
                api.logging().logToError("[Persistent Storage] Failed to save findings: " + ex.getMessage());
            }
        }

        return success;
    }

    /**
     * Loads persisted findings, passwords, domains, and classifications from disk.
     * Returns total findings loaded.
     */
    public synchronized int loadData(ResponseScanEngine scanEngine, InScopeDomainManager domainManager) {
        File dir = getStorageDirectory();
        if (dir == null || !dir.exists()) return 0;

        int loadedCount = 0;

        // 1. Load config
        File configFile = new File(dir, CONFIG_FILE);
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                Properties props = new Properties();
                props.load(fis);

                if (scanEngine != null && scanEngine.getPasswordScanner() != null) {
                    PasswordScanner ps = scanEngine.getPasswordScanner();
                    ps.setCaseSensitive(Boolean.parseBoolean(props.getProperty("passwords_case_sensitive", "false")));
                    int pwCount = Integer.parseInt(props.getProperty("passwords_count", "0"));
                    for (int i = 0; i < pwCount; i++) {
                        String pw = props.getProperty("password." + i);
                        if (pw != null) {
                            ps.addPassword(pw);
                        }
                    }
                }

                if (domainManager != null) {
                    int domCount = Integer.parseInt(props.getProperty("domains_count", "0"));
                    List<String> toSelect = new ArrayList<>();
                    for (int i = 0; i < domCount; i++) {
                        String dom = props.getProperty("domain." + i);
                        if (dom != null && !dom.isBlank()) {
                            domainManager.addDomain(dom);
                            boolean isSel = Boolean.parseBoolean(props.getProperty("domain_selected." + i, "true"));
                            if (isSel) {
                                toSelect.add(dom);
                            }
                            int cnt = Integer.parseInt(props.getProperty("domain_count." + i, "0"));
                            for (int c = 0; c < cnt; c++) {
                                domainManager.registerFinding(dom);
                            }
                        }
                    }
                    if (!toSelect.isEmpty()) {
                        domainManager.setSelectedDomains(toSelect);
                    }
                }

                if (scanEngine != null && scanEngine.getSecretClassificationManager() != null) {
                    SecretClassificationManager scm = scanEngine.getSecretClassificationManager();
                    for (String key : props.stringPropertyNames()) {
                        if (key.startsWith("secret_type_class.")) {
                            String ruleName = key.substring("secret_type_class.".length());
                            String clStr = props.getProperty(key);
                            try {
                                SecretClassification cl = SecretClassification.valueOf(clStr);
                                scm.markSecretType(ruleName, cl);
                            } catch (Exception ignored) {}
                        }
                    }
                }
            } catch (Exception ex) {
                if (api != null && api.logging() != null) {
                    api.logging().logToError("[Persistent Storage] Failed to load config: " + ex.getMessage());
                }
            }
        }

        // 2. Load findings binary
        File findingsFile = new File(dir, FINDINGS_FILE);
        if (findingsFile.exists()) {
            SecretClassificationManager scm = (scanEngine != null) ? scanEngine.getSecretClassificationManager() : null;

            try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(findingsFile)))) {
                int magic = in.readInt();
                if (magic != MAGIC_HEADER) {
                    throw new IOException("Invalid storage file magic header: " + Integer.toHexString(magic));
                }
                int version = in.readInt();
                if (version != FORMAT_VERSION) {
                    throw new IOException("Unsupported storage version: " + version);
                }
                int count = in.readInt();

                for (int i = 0; i < count; i++) {
                    int id = in.readInt();
                    String catStr = readSafeString(in);
                    FindingCategory category = FindingCategory.valueOf(catStr);
                    String patternName = readSafeString(in);
                    String matchValue = readSafeString(in);
                    String matchLocation = readSafeString(in);
                    String method = readSafeString(in);
                    String url = readSafeString(in);
                    String host = readSafeString(in);
                    String path = readSafeString(in);
                    short statusCode = in.readShort();
                    String contentType = readSafeString(in);
                    int contentLength = in.readInt();
                    String timeString = readSafeString(in);
                    int startOffset = in.readInt();
                    int endOffset = in.readInt();

                    HttpRequest req = null;
                    boolean hasReq = in.readBoolean();
                    if (hasReq) {
                        String svcHost = readSafeString(in);
                        int svcPort = in.readInt();
                        boolean svcSecure = in.readBoolean();
                        int reqLen = in.readInt();
                        byte[] reqBytes = in.readNBytes(reqLen);

                        HttpService svc = (svcHost != null && !svcHost.isEmpty())
                                ? HttpService.httpService(svcHost, svcPort, svcSecure)
                                : null;
                        ByteArray ba = ByteArray.byteArray(reqBytes);
                        req = svc != null ? HttpRequest.httpRequest(svc, ba) : HttpRequest.httpRequest(ba);
                    }

                    HttpResponse resp = null;
                    boolean hasResp = in.readBoolean();
                    if (hasResp) {
                        int respLen = in.readInt();
                        byte[] respBytes = in.readNBytes(respLen);
                        resp = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
                    }

                    HttpRequestResponse reqResp = null;
                    if (req != null || resp != null) {
                        HttpRequest effectiveReq = req != null ? req : HttpRequest.httpRequest();
                        HttpResponse effectiveResp = resp != null ? resp : HttpResponse.httpResponse();
                        reqResp = HttpRequestResponse.httpRequestResponse(effectiveReq, effectiveResp);
                    }

                    boolean hasIndivClass = in.readBoolean();
                    String indivClassStr = null;
                    if (hasIndivClass) {
                        indivClassStr = readSafeString(in);
                    }

                    FindingEntry entry = new FindingEntry(
                            id,
                            category,
                            patternName,
                            matchValue,
                            matchLocation,
                            method,
                            url,
                            host,
                            path,
                            statusCode,
                            contentType,
                            contentLength,
                            reqResp,
                            timeString,
                            startOffset,
                            endOffset
                    );

                    if (scanEngine != null) {
                        InspectorDataStore ds = scanEngine.getDataStore(category);
                        if (ds != null) {
                            if (ds.addEntry(entry)) {
                                loadedCount++;
                            }
                        }
                    }

                    if (hasIndivClass && indivClassStr != null && scm != null) {
                        try {
                            scm.markRequest(entry, SecretClassification.valueOf(indivClassStr));
                        } catch (Exception ignored) {}
                    }
                }
            } catch (Exception ex) {
                if (api != null && api.logging() != null) {
                    api.logging().logToError("[Persistent Storage] Failed to load findings: " + ex.getMessage());
                }
            }
        }

        if (api != null && api.logging() != null && loadedCount > 0) {
            api.logging().logToOutput("[Response Inspector] Loaded " + loadedCount + " persisted findings from: " + dir.getAbsolutePath());
        }

        return loadedCount;
    }

    /**
     * Explicitly deletes stored data files from disk upon user request.
     */
    public synchronized boolean deleteStoredData() {
        File dir = getStorageDirectory();
        if (dir == null || !dir.exists()) return true;

        boolean allDeleted = true;
        File[] files = dir.listFiles((d, name) ->
                name.equals(FINDINGS_FILE) || name.equals(CONFIG_FILE)
                        || name.endsWith(".tmp") || name.endsWith(".bak"));

        if (files != null) {
            for (File f : files) {
                if (!f.delete()) {
                    allDeleted = false;
                }
            }
        }

        if (api != null && api.logging() != null) {
            api.logging().logToOutput("[Response Inspector] Persistent data files explicitly deleted from: " + dir.getAbsolutePath());
        }

        return allDeleted;
    }

    public long getStorageSizeBytes() {
        File dir = getStorageDirectory();
        if (dir == null || !dir.exists()) return 0;
        long total = 0;
        File f1 = new File(dir, FINDINGS_FILE);
        if (f1.exists()) total += f1.length();
        File f2 = new File(dir, CONFIG_FILE);
        if (f2.exists()) total += f2.length();
        return total;
    }

    public String getLastModifiedFormatted() {
        File dir = getStorageDirectory();
        if (dir == null || !dir.exists()) return "Never";
        File f = new File(dir, FINDINGS_FILE);
        if (!f.exists()) f = new File(dir, CONFIG_FILE);
        if (!f.exists()) return "Never";

        LocalDateTime dt = LocalDateTime.ofInstant(Instant.ofEpochMilli(f.lastModified()), ZoneId.systemDefault());
        return dt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public void shutdown() {
        saveNow();
        autoSaveExecutor.shutdown();
        try {
            if (!autoSaveExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                autoSaveExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            autoSaveExecutor.shutdownNow();
        }
    }

    private static void writeSafeString(DataOutputStream out, String val) throws IOException {
        if (val == null) {
            out.writeBoolean(false);
        } else {
            out.writeBoolean(true);
            out.writeUTF(val);
        }
    }

    private static String readSafeString(DataInputStream in) throws IOException {
        if (!in.readBoolean()) {
            return null;
        }
        return in.readUTF();
    }
}
