// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.gwtmap.model.GWTDataStore;
import com.littlespidy.gwtmap.model.GWTMethod;
import com.littlespidy.gwtmap.model.GWTModuleInfo;
import com.littlespidy.gwtmap.model.GWTService;
import com.littlespidy.gwtmap.model.GwtHttpHistoryEntry;
import com.littlespidy.gwtmap.ui.GWTMapTab;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles persistent data storage across sessions for Windows, Linux, and macOS.
 * Detects Burp project file folder or prompts for folder if temporary project.
 *
 * @author littlespidy
 */
public class GWTMapPersistenceManager {

    public static final String PREF_KEY_GLOBAL_DIR = "burpsuite_extensions_last_session_dir_littlespidy";
    public static final String PREF_STORAGE_DIR = "gwtmap_storage_dir";
    public static final String SESSION_FILENAME = "gwtmap_session.json";

    private final MontoyaApi api;
    private final Gson gson;
    private File storageDirectory;
    private volatile File activeSessionFile = null;
    private final JLabel sessionStatusLabel;
    private GWTMapTab mainTab;
    private GWTDataStore dataStore;

    public GWTMapPersistenceManager(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    }

    public void bindContext(GWTMapTab mainTab, GWTDataStore dataStore) {
        this.mainTab = mainTab;
        this.dataStore = dataStore;
    }

    /**
     * Resolves the storage directory:
     * 1. If a Burp project file (.burp) is active, uses the project file's folder.
     * 2. If temporary project, prompts the user (or uses remembered preference).
     */
    public synchronized File resolveStorageDirectory(Component parent) {
        if (storageDirectory != null && storageDirectory.exists()) {
            return storageDirectory;
        }

        // 1. Try detecting project file from CLI arguments
        File projectDir = detectProjectDirFromArgs();
        if (projectDir != null && projectDir.exists()) {
            this.storageDirectory = projectDir;
            return storageDirectory;
        }

        // 2. Try detecting project file from Frame titles (Burp Suite Pro window title contains project path)
        projectDir = detectProjectDirFromFrames();
        if (projectDir != null && projectDir.exists()) {
            this.storageDirectory = projectDir;
            return storageDirectory;
        }

        // 3. Temporary project: check if already remembered in preferences
        String savedDir = null;
        try {
            if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
                savedDir = api.persistence().preferences().getString(PREF_STORAGE_DIR);
            }
        } catch (Throwable ignored) {}

        if (savedDir != null && !savedDir.isBlank()) {
            File dir = new File(savedDir.trim());
            if (dir.exists() && dir.isDirectory()) {
                this.storageDirectory = dir;
                return storageDirectory;
            }
        }

        // 4. Prompt user to select folder for temporary project
        File chosen = promptUserForDirectory(parent);
        if (chosen != null) {
            this.storageDirectory = chosen;
            saveStoragePreference(chosen.getAbsolutePath());
            return storageDirectory;
        }

        // 5. Fallback: user home directory (~/.gwtmap)
        File fallback = new File(System.getProperty("user.home"), ".gwtmap");
        if (!fallback.exists()) {
            fallback.mkdirs();
        }
        this.storageDirectory = fallback;
        saveStoragePreference(fallback.getAbsolutePath());
        return storageDirectory;
    }

    public synchronized File getStorageDirectory() {
        return storageDirectory;
    }

    public synchronized void setStorageDirectory(File dir) {
        if (dir != null) {
            if (!dir.exists()) {
                dir.mkdirs();
            }
            this.storageDirectory = dir;
            saveStoragePreference(dir.getAbsolutePath());
        }
    }

    private void saveStoragePreference(String path) {
        try {
            if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
                api.persistence().preferences().setString(PREF_STORAGE_DIR, path);
            }
        } catch (Throwable ignored) {}
    }

    public File promptUserForDirectory(Component parent) {
        try {
            int option = JOptionPane.showConfirmDialog(
                    parent,
                    "Temporary project detected (or no project file opened).\n" +
                    "Would you like to choose a directory to persist GWTMap session data across restarts?",
                    "GWTMap Session Storage",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );

            if (option == JOptionPane.YES_OPTION) {
                JFileChooser chooser = new JFileChooser();
                chooser.setDialogTitle("Select Folder for GWTMap Session Storage");
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);

                int result = chooser.showOpenDialog(parent);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selected = chooser.getSelectedFile();
                    if (selected != null) {
                        if (!selected.exists()) {
                            selected.mkdirs();
                        }
                        return selected;
                    }
                }
            }
        } catch (Throwable e) {
            if (api != null) {
                api.logging().logToError("Error prompting user for storage folder: " + e.getMessage());
            }
        }
        return null;
    }

    private File detectProjectDirFromArgs() {
        if (api == null || api.burpSuite() == null) return null;
        try {
            List<String> args = api.burpSuite().commandLineArguments();
            if (args != null) {
                for (String arg : args) {
                    if (arg.startsWith("--project-file=")) {
                        String path = arg.substring("--project-file=".length()).trim();
                        File f = new File(path);
                        if (f.exists() && f.getParentFile() != null) {
                            return f.getParentFile();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private File detectProjectDirFromFrames() {
        try {
            Frame[] frames = Frame.getFrames();
            if (frames == null) return null;

            // Pattern for Windows (e.g. C:\path\project.burp) and Unix/Mac (e.g. /path/project.burp)
            Pattern winPattern = Pattern.compile("([a-zA-Z]:\\\\[^\\r\\n*?\"<>|]+?\\.burp)", Pattern.CASE_INSENSITIVE);
            Pattern unixPattern = Pattern.compile("(/[^\\r\\n*?\"<>|]+?\\.burp)", Pattern.CASE_INSENSITIVE);

            for (Frame f : frames) {
                String title = f.getTitle();
                if (title != null && title.contains("Burp Suite") && !title.toLowerCase().contains("temporary project")) {
                    Matcher m = winPattern.matcher(title);
                    if (m.find()) {
                        File p = new File(m.group(1));
                        if (p.exists() && p.getParentFile() != null) {
                            return p.getParentFile();
                        }
                    }
                    m = unixPattern.matcher(title);
                    if (m.find()) {
                        File p = new File(m.group(1));
                        if (p.exists() && p.getParentFile() != null) {
                            return p.getParentFile();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}
        return null;
    }

    public File getSessionFile() {
        if (activeSessionFile != null) {
            return activeSessionFile;
        }
        if (storageDirectory == null) {
            resolveStorageDirectory(null);
        }
        return new File(storageDirectory, SESSION_FILENAME);
    }

    public File getActiveSessionFile() {
        return activeSessionFile;
    }

    public void setActiveSessionFile(File file) {
        this.activeSessionFile = file;
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
        this.activeSessionFile = file;
        this.storageDirectory = file.getParentFile();
        SessionSnapshot snapshot = loadFromFile(dataStore, file);
        if (snapshot != null && mainTab != null) {
            mainTab.applySnapshot(snapshot);
        }
        updateStatusLabel("Session: " + file.getName() + " (Auto-save Enabled)");
    }

    public synchronized void createNewSessionFile(File file) {
        if (file == null) return;
        this.activeSessionFile = file;
        this.storageDirectory = file.getParentFile();
        if (mainTab != null) {
            save(dataStore, mainTab.getTargetUrl(), mainTab.getBaseUrl(), mainTab.getCustomHeaders());
        }
        updateStatusLabel("Session: " + file.getName() + " (Auto-save Enabled)");
    }

    public synchronized void startTemporarySession() {
        this.activeSessionFile = null;
        updateStatusLabel("Session: [In-Memory / Temporary]");
    }

    public synchronized void saveActiveSession() {
        if (activeSessionFile != null) {
            if (mainTab != null) {
                save(dataStore, mainTab.getTargetUrl(), mainTab.getBaseUrl(), mainTab.getCustomHeaders());
            }
            updateStatusLabel("Session: " + activeSessionFile.getName() + " (Auto-save Enabled)");
        } else {
            saveAsSession(mainTab);
        }
    }

    public synchronized void saveAsSession(Component parent) {
        File lastDir = getLastDirectory();
        JFileChooser chooser = new JFileChooser(lastDir);
        chooser.setDialogTitle("Save GWTMap Session As...");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        chooser.setSelectedFile(new File(lastDir, "gwtmap_session.json"));

        int res = chooser.showSaveDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            rememberDirectory(sel.getParent());
            this.activeSessionFile = sel;
            this.storageDirectory = sel.getParentFile();
            if (mainTab != null) {
                save(dataStore, mainTab.getTargetUrl(), mainTab.getBaseUrl(), mainTab.getCustomHeaders());
            }
            updateStatusLabel("Session: " + sel.getName() + " (Auto-save Enabled)");
            if (!GraphicsEnvironment.isHeadless() && !Boolean.getBoolean("java.awt.headless") && parent != null && parent.isShowing()) {
                JOptionPane.showMessageDialog(parent, "Session saved successfully to:\n" + sel.getAbsolutePath(),
                        "Session Saved", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    public synchronized void loadSessionPrompt(Component parent) {
        File lastDir = getLastDirectory();
        JFileChooser chooser = new JFileChooser(lastDir);
        chooser.setDialogTitle("Open GWTMap Session File");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));

        int res = chooser.showOpenDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            rememberDirectory(sel.getParent());
            openSessionFile(sel);
        }
    }

    public synchronized void offboardSession(Component parent) {
        if (!GraphicsEnvironment.isHeadless() && !Boolean.getBoolean("java.awt.headless") && parent != null && parent.isShowing()) {
            int confirm = JOptionPane.showConfirmDialog(
                    parent,
                    "Offboarding will save pending changes to the active session (if any),\n" +
                            "reset all services, methods, HTTP history, and fuzzer state to a completely fresh state,\n" +
                            "and unbind the current session file.\n\n" +
                            "Are you sure you want to offboard this session?",
                    "Confirm Session Offboard",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
        }

        if (activeSessionFile != null && mainTab != null) {
            save(dataStore, mainTab.getTargetUrl(), mainTab.getBaseUrl(), mainTab.getCustomHeaders());
        }

        if (mainTab != null) {
            mainTab.resetAll();
        }

        this.activeSessionFile = null;
        updateStatusLabel("Session: [In-Memory / Temporary]");

        if (!GraphicsEnvironment.isHeadless() && !Boolean.getBoolean("java.awt.headless") && parent != null && parent.isShowing()) {
            JOptionPane.showMessageDialog(
                    parent,
                    "Session successfully offboarded.\nWorkspace reset to a clean state.",
                    "Session Offboarded",
                    JOptionPane.INFORMATION_MESSAGE
            );
        }
    }

    public JComponent createSessionToolbar() {
        JPanel bar = new JPanel(new BorderLayout(8, 0));
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JLabel titleLabel = new JLabel("Session:");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        leftPanel.add(titleLabel);

        JButton newBtn = new JButton("New Session");
        newBtn.setToolTipText("Create a new session file and bind to it");
        newBtn.addActionListener(e -> {
            File lastDir = getLastDirectory();
            JFileChooser chooser = new JFileChooser(lastDir);
            chooser.setDialogTitle("Select Directory to Save New Session");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int res = chooser.showOpenDialog(bar);
            if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                File dir = chooser.getSelectedFile();
                rememberDirectory(dir.getAbsolutePath());
                String name = JOptionPane.showInputDialog(bar, "Enter session filename:", "gwtmap_session.json");
                if (name != null && !name.isBlank()) {
                    if (!name.toLowerCase().endsWith(".json")) name = name + ".json";
                    createNewSessionFile(new File(dir, name.trim()));
                }
            }
        });

        JButton saveBtn = new JButton("Save Now");
        saveBtn.setToolTipText("Save current session state to the active file");
        saveBtn.addActionListener(e -> saveActiveSession());

        JButton saveAsBtn = new JButton("Save As...");
        saveAsBtn.setToolTipText("Save current session to a new file");
        saveAsBtn.addActionListener(e -> saveAsSession(bar));

        JButton loadBtn = new JButton("Load Session...");
        loadBtn.setToolTipText("Load a previously saved session file");
        loadBtn.addActionListener(e -> loadSessionPrompt(bar));

        JButton offboardBtn = new JButton("Offboard Session");
        offboardBtn.setToolTipText("Reset workspace and unbind the active session file");
        offboardBtn.addActionListener(e -> offboardSession(bar));

        leftPanel.add(newBtn);
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
                lastDir = api.persistence().preferences().getString(PREF_KEY_GLOBAL_DIR);
                if (lastDir == null || lastDir.isBlank()) {
                    lastDir = api.persistence().preferences().getString("burp_extensions_last_session_dir_littlespidy");
                }
                if (lastDir == null || lastDir.isBlank()) {
                    lastDir = api.persistence().preferences().getString(PREF_STORAGE_DIR);
                }
            } catch (Exception ignored) {}
        }
        if (lastDir != null && !lastDir.isBlank()) {
            File d = new File(lastDir);
            if (d.exists() && d.isDirectory()) return d;
        }
        if (storageDirectory != null && storageDirectory.exists()) {
            return storageDirectory;
        }
        return new File(System.getProperty("user.home", "."));
    }

    private void rememberDirectory(String dirPath) {
        if (api != null && api.persistence() != null && api.persistence().preferences() != null && dirPath != null) {
            try {
                api.persistence().preferences().setString(PREF_KEY_GLOBAL_DIR, dirPath);
                api.persistence().preferences().setString(PREF_STORAGE_DIR, dirPath);
            } catch (Exception ignored) {}
        }
    }

    public void shutdown() {
        if (activeSessionFile != null && mainTab != null) {
            save(dataStore, mainTab.getTargetUrl(), mainTab.getBaseUrl(), mainTab.getCustomHeaders());
        }
    }

    /**
     * Saves complete session data to gwtmap_session.json.
     */
    public synchronized boolean save(GWTDataStore dataStore, String targetUrl, String permutationUrl, String customHeaders) {
        return saveToFile(getSessionFile(), dataStore, targetUrl, permutationUrl, customHeaders);
    }

    public synchronized boolean saveToFile(File file, GWTDataStore dataStore, String targetUrl, String permutationUrl, String customHeaders) {
        try {
            if (file.getParentFile() != null && !file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
            }

            SessionSnapshot snapshot = new SessionSnapshot();
            snapshot.targetUrl = targetUrl != null ? targetUrl : "";
            snapshot.permutationUrl = permutationUrl != null ? permutationUrl : "";
            snapshot.customHeaders = customHeaders != null ? customHeaders : "";
            snapshot.moduleInfo = dataStore.getModuleInfo();
            snapshot.services = dataStore.getAllServices();
            snapshot.rawCode = dataStore.getRawCode();
            snapshot.cleanedCode = dataStore.getCleanedCode();

            // Methods
            for (GWTMethod m : dataStore.getAllMethods()) {
                MethodDto md = new MethodDto();
                md.id = m.getId();
                md.methodName = m.getMethodName();
                md.serviceProxy = m.getServiceProxy();
                md.rmtSvcIntName = m.getRmtSvcIntName();
                md.paramCount = m.getParamCount();
                md.methodSignature = new ArrayList<>(m.getMethodSignature());
                md.fullEndpointUrl = m.getFullEndpointUrl();
                md.methodRpcCall = m.getMethodRpcCall();
                md.rawRpcCall = m.getRawRpcCall();
                md.complexTypes = new ArrayList<>(m.getComplexTypes());
                md.probed = m.isProbed();
                md.probeStatusCode = m.getProbeStatusCode();
                md.probeResponseLength = m.getProbeResponseLength();
                md.probeResponseBody = m.getProbeResponseBody();
                md.probeResponseTimeMs = m.getProbeResponseTimeMs();
                md.probeNotes = m.getProbeNotes();
                if (m.getProbeRequest() != null) {
                    md.rawProbeRequest = m.getProbeRequest().toString();
                }
                if (m.getProbeResponse() != null) {
                    md.rawProbeResponse = m.getProbeResponse().toString();
                }
                if (m.getService() != null) {
                    md.serviceStrongName = m.getService().getStrongName();
                    md.servicePath = m.getService().getServicePath();
                }
                snapshot.methods.add(md);
            }

            // HTTP History
            for (GwtHttpHistoryEntry h : dataStore.getHttpHistory()) {
                HistoryDto hd = new HistoryDto();
                hd.id = h.getId();
                hd.timestamp = h.getTimestamp();
                hd.type = h.getType();
                hd.method = h.getMethod();
                hd.methodName = h.getMethodName();
                hd.url = h.getUrl();
                hd.statusCode = h.getStatusCode();
                hd.responseLength = h.getResponseLength();
                hd.durationMs = h.getDurationMs();
                if (h.getRequestResponse() != null) {
                    if (h.getRequestResponse().request() != null) {
                        hd.rawRequest = h.getRequestResponse().request().toString();
                    }
                    if (h.getRequestResponse().response() != null) {
                        hd.rawResponse = h.getRequestResponse().response().toString();
                    }
                }
                snapshot.httpHistory.add(hd);
            }

            String json = gson.toJson(snapshot);
            Files.writeString(file.toPath(), json, StandardCharsets.UTF_8);
            if (api != null) {
                api.logging().logToOutput("[GWTMap] Session successfully saved to: " + file.getAbsolutePath());
            }
            return true;
        } catch (Throwable e) {
            if (api != null) {
                api.logging().logToError("[GWTMap] Error saving session: " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Loads session data from gwtmap_session.json if available.
     * Returns SessionSnapshot with UI field values (or null if no file).
     */
    public synchronized SessionSnapshot load(GWTDataStore dataStore) {
        return loadFromFile(dataStore, getSessionFile());
    }

    public synchronized SessionSnapshot loadFromFile(GWTDataStore dataStore, File file) {
        try {
            if (file == null || !file.exists()) {
                return null;
            }

            String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            if (json == null || json.isBlank()) return null;

            SessionSnapshot snapshot = gson.fromJson(json, SessionSnapshot.class);
            if (snapshot == null) return null;

            // Restore DataStore
            if (snapshot.moduleInfo != null) {
                dataStore.setModuleInfo(snapshot.moduleInfo);
            }
            if (snapshot.services != null) {
                dataStore.setServices(snapshot.services);
            }
            if (snapshot.rawCode != null) {
                dataStore.setRawCode(snapshot.rawCode);
            }
            if (snapshot.cleanedCode != null) {
                dataStore.setCleanedCode(snapshot.cleanedCode);
            }

            // Restore methods
            if (snapshot.methods != null) {
                List<GWTMethod> restoredMethods = new ArrayList<>();
                for (MethodDto md : snapshot.methods) {
                    GWTMethod m = new GWTMethod(md.id, md.methodName, md.serviceProxy, md.rmtSvcIntName, md.paramCount, md.methodSignature);
                    m.setFullEndpointUrl(md.fullEndpointUrl);
                    m.setMethodRpcCall(md.methodRpcCall);
                    m.setComplexTypes(md.complexTypes);
                    if (md.serviceStrongName != null) {
                        m.setService(new GWTService(md.servicePath, md.serviceStrongName));
                    }

                    if (md.probed) {
                        HttpRequest req = null;
                        HttpResponse resp = null;
                        try {
                            if (md.rawProbeRequest != null && !md.rawProbeRequest.isEmpty()) {
                                req = HttpRequest.httpRequest(md.rawProbeRequest);
                            }
                            if (md.rawProbeResponse != null && !md.rawProbeResponse.isEmpty()) {
                                resp = HttpResponse.httpResponse(md.rawProbeResponse);
                            }
                        } catch (Throwable ignored) {}

                        m.restoreProbeResult(req, resp, md.probeStatusCode, md.probeResponseLength,
                                md.probeResponseBody, md.probeResponseTimeMs, md.probeNotes);
                    }
                    restoredMethods.add(m);
                }
                dataStore.setMethods(restoredMethods);
            }

            // Restore HTTP History
            if (snapshot.httpHistory != null) {
                dataStore.clearHttpHistory();
                for (HistoryDto hd : snapshot.httpHistory) {
                    HttpRequestResponse rr = null;
                    try {
                        HttpRequest req = (hd.rawRequest != null && !hd.rawRequest.isEmpty())
                                ? HttpRequest.httpRequest(hd.rawRequest) : null;
                        HttpResponse resp = (hd.rawResponse != null && !hd.rawResponse.isEmpty())
                                ? HttpResponse.httpResponse(hd.rawResponse) : null;
                        if (req != null) {
                            rr = HttpRequestResponse.httpRequestResponse(req, resp);
                        }
                    } catch (Throwable ignored) {}

                    GwtHttpHistoryEntry entry = new GwtHttpHistoryEntry(
                            hd.id, hd.timestamp, hd.type, hd.method,
                            hd.methodName != null ? hd.methodName : "",
                            hd.url, hd.statusCode, hd.responseLength, hd.durationMs, rr
                    );
                    dataStore.addHttpHistoryEntry(entry);
                }
            }

            if (api != null) {
                api.logging().logToOutput("[GWTMap] Session restored from: " + file.getAbsolutePath());
            }
            return snapshot;
        } catch (Throwable e) {
            if (api != null) {
                api.logging().logToError("[GWTMap] Error loading session: " + e.getMessage());
            }
            return null;
        }
    }

    /**
     * Clears persisted session file.
     */
    public synchronized boolean clear() {
        try {
            File file = getSessionFile();
            if (file.exists()) {
                return file.delete();
            }
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    // -- DTOs -----------------------------------------------------------------

    public static class SessionSnapshot {
        public String targetUrl = "";
        public String permutationUrl = "";
        public String customHeaders = "";
        public GWTModuleInfo moduleInfo = new GWTModuleInfo();
        public List<GWTService> services = new ArrayList<>();
        public List<MethodDto> methods = new ArrayList<>();
        public List<HistoryDto> httpHistory = new ArrayList<>();
        public String rawCode = "";
        public String cleanedCode = "";
    }

    public static class MethodDto {
        public int id;
        public String methodName;
        public String serviceProxy;
        public String rmtSvcIntName;
        public String paramCount;
        public List<String> methodSignature = new ArrayList<>();
        public String fullEndpointUrl;
        public String methodRpcCall;
        public String rawRpcCall;
        public List<String> complexTypes = new ArrayList<>();
        public boolean probed;
        public int probeStatusCode;
        public int probeResponseLength;
        public String probeResponseBody;
        public long probeResponseTimeMs;
        public String probeNotes;
        public String rawProbeRequest;
        public String rawProbeResponse;
        public String serviceStrongName;
        public String servicePath;
    }

    public static class HistoryDto {
        public int id;
        public String timestamp;
        public String type;
        public String method;
        public String methodName;
        public String url;
        public int statusCode;
        public int responseLength;
        public long durationMs;
        public String rawRequest;
        public String rawResponse;
    }
}
