// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.apiinspector.model.*;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.GeneratedVariationItem;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.ReferenceRequestEntry;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.*;
import com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy;
import com.littlespidy.apiinspector.ui.RequestSessionPanel_littlespidy;
import com.littlespidy.apiinspector.ui.ResAPIVersionFinderTab_littlespidy;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
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

    public static final String PREF_KEY_GLOBAL_DIR = "burpsuite_extensions_last_session_dir_littlespidy";
    public static final String PREF_KEY_STORAGE_DIR = "api_inspector_storage_dir";
    public static final String SESSION_FILENAME = "api_inspector_session.json";
    private static final String DEFAULT_FALLBACK_DIR = ".burp_api_inspector";

    private final MontoyaApi api;
    private final Gson gson;
    private File storageDirectory;
    private volatile File activeSessionFile = null;
    private final JLabel sessionStatusLabel;

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
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
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
        if (activeSessionFile != null) {
            return activeSessionFile;
        }
        return new File(getStorageDirectory(), SESSION_FILENAME);
    }

    public File getActiveSessionFile() {
        return activeSessionFile;
    }

    public void setActiveSessionFile(File file) {
        this.activeSessionFile = file;
    }

    /**
     * Schedules a debounced asynchronous save (1500ms delay) for the entire root tab.
     */
    public synchronized void saveAsync(APIInspectorTab_littlespidy rootTab) {
        if (activeSessionFile == null) {
            return;
        }
        if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
            pendingSaveTask.cancel(false);
        }
        pendingSaveTask = debounceExecutor.schedule(() -> saveSync(rootTab), 1500, TimeUnit.MILLISECONDS);
    }

    public synchronized void saveAsync(ResAPIVersionFinderTab_littlespidy tab) {
        if (activeSessionFile == null) {
            return;
        }
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
        saveSyncInternal(tab, null, null, null, null, null, null);
    }

    public void saveSync(APIInspectorTab_littlespidy rootTab) {
        if (rootTab == null) return;
        saveSyncInternal(rootTab.getVersionFinderTab(),
                rootTab.getDocStrategyTab() != null ? rootTab.getDocStrategyTab().getAllEntries() : null,
                rootTab.getEndpointDiscoveryTab() != null ? rootTab.getEndpointDiscoveryTab().getAllEntries() : null,
                rootTab.getImportTab() != null ? rootTab.getImportTab().getAllCollections() : null,
                rootTab.getAuthTestingTab() != null ? rootTab.getAuthTestingTab().getAllProfiles() : null,
                rootTab.getAuthTestingTab() != null ? rootTab.getAuthTestingTab().getAllResults() : null,
                rootTab.getHiddenApiStorageTab() != null ? rootTab.getHiddenApiStorageTab().getAllEndpoints() : null);
    }

    private void saveSyncInternal(
            ResAPIVersionFinderTab_littlespidy tab,
            List<ReferenceRequestEntry> docEntries,
            List<ReferenceRequestEntry> endpointEntries,
            List<ImportedCollection_littlespidy> collections,
            List<AuthProfile_littlespidy> profiles,
            List<AuthTestResult_littlespidy> testResults,
            List<HiddenEndpoint_littlespidy> hiddenEndpoints) {

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

                if (collections != null) {
                    for (ImportedCollection_littlespidy c : collections) {
                        root.importedCollections.add(serializeImportedCollection(c));
                    }
                }

                if (profiles != null) {
                    for (AuthProfile_littlespidy p : profiles) {
                        root.authProfiles.add(serializeAuthProfile(p));
                    }
                }

                if (testResults != null) {
                    for (AuthTestResult_littlespidy r : testResults) {
                        root.authTestResults.add(serializeAuthTestResult(r));
                    }
                }

                if (hiddenEndpoints != null) {
                    for (HiddenEndpoint_littlespidy h : hiddenEndpoints) {
                        root.hiddenEndpoints.add(serializeHiddenEndpoint(h));
                    }
                }

                if (rootTab.getRequestResponseViewerTab() != null && rootTab.getRequestResponseViewerTab().getSessionStore() != null) {
                    root.sessionStore = serializeSessionStore(rootTab.getRequestResponseViewerTab().getSessionStore());
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
     * Standardized session initialization invoked on startup.
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
        this.activeSessionFile = file;
        this.storageDirectory = file.getParentFile();
        loadSession(this.rootTab);
        updateStatusLabel("Session: " + file.getName() + " (Auto-save Enabled)");
    }

    public synchronized void createNewSessionFile(File file) {
        if (file == null) return;
        this.activeSessionFile = file;
        this.storageDirectory = file.getParentFile();
        if (this.rootTab != null) {
            saveSync(this.rootTab);
        }
        updateStatusLabel("Session: " + file.getName() + " (Auto-save Enabled)");
    }

    public synchronized void startTemporarySession() {
        this.activeSessionFile = null;
        updateStatusLabel("Session: [In-Memory / Temporary]");
    }

    public synchronized void saveActiveSession() {
        if (activeSessionFile != null) {
            if (this.rootTab != null) {
                saveSync(this.rootTab);
            }
            updateStatusLabel("Session: " + activeSessionFile.getName() + " (Auto-save Enabled)");
        } else {
            saveAsSession(this.rootTab);
        }
    }

    public synchronized void saveAsSession(Component parent) {
        File lastDir = getLastDirectory();
        JFileChooser chooser = new JFileChooser(lastDir);
        chooser.setDialogTitle("Save API Inspector Session As...");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        chooser.setSelectedFile(new File(lastDir, "api_inspector_session.json"));

        int res = chooser.showSaveDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            rememberDirectory(sel.getParent());
            this.activeSessionFile = sel;
            this.storageDirectory = sel.getParentFile();
            if (rootTab != null) {
                saveSync(rootTab);
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
        chooser.setDialogTitle("Open API Inspector Session File");
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
                            "reset all version tabs, imported collections, and auth profiles to a completely fresh state,\n" +
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

        if (activeSessionFile != null && rootTab != null) {
            saveSync(rootTab);
        }

        if (rootTab != null) {
            rootTab.resetWorkspace();
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
                String name = JOptionPane.showInputDialog(bar, "Enter session filename:", "api_inspector_session.json");
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
                    lastDir = api.persistence().preferences().getString(PREF_KEY_STORAGE_DIR);
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
                api.persistence().preferences().setString(PREF_KEY_STORAGE_DIR, dirPath);
            } catch (Exception ignored) {}
        }
    }

    public void shutdown() {
        if (activeSessionFile != null && rootTab != null) {
            saveSync(rootTab);
        }
        debounceExecutor.shutdown();
        try {
            if (!debounceExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                debounceExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            debounceExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Prompts the user on extension startup if a previous session exists, allowing them
     * to choose between restoring the existing session or starting a fresh new session.
     */
    public void promptSessionStartup(Component parent, APIInspectorTab_littlespidy rootTab) {
        initializeSessionOnStartup(parent, null);
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

                    // 4. Restore Imported Collections
                    if (root.importedCollections != null && !root.importedCollections.isEmpty()) {
                        List<ImportedCollection_littlespidy> colList = new ArrayList<>();
                        for (ImportedCollectionDTO cDto : root.importedCollections) {
                            ImportedCollection_littlespidy col = deserializeImportedCollection(cDto);
                            if (col != null) colList.add(col);
                        }
                        rootTab.getImportTab().setCollections(colList);
                    }

                    // 5. Restore Authentication Profiles
                    if (root.authProfiles != null && !root.authProfiles.isEmpty()) {
                        List<AuthProfile_littlespidy> profList = new ArrayList<>();
                        for (AuthProfileDTO pDto : root.authProfiles) {
                            AuthProfile_littlespidy prof = deserializeAuthProfile(pDto);
                            if (prof != null) profList.add(prof);
                        }
                        rootTab.getAuthTestingTab().setProfiles(profList);
                    }

                    // 6. Restore Authentication Test Results
                    if (root.authTestResults != null && !root.authTestResults.isEmpty()) {
                        List<AuthTestResult_littlespidy> resList = new ArrayList<>();
                        for (AuthTestResultDTO rDto : root.authTestResults) {
                            AuthTestResult_littlespidy res = deserializeAuthTestResult(rDto);
                            if (res != null) resList.add(res);
                        }
                        rootTab.getAuthTestingTab().setResults(resList);
                    }

                    // 7. Restore Session Store
                    if (root.sessionStore != null && rootTab.getRequestResponseViewerTab() != null) {
                        rootTab.getRequestResponseViewerTab().setSessionStore(deserializeSessionStore(root.sessionStore));
                    }

                    // 8. Restore Hidden API Storage Endpoints
                    if (root.hiddenEndpoints != null && !root.hiddenEndpoints.isEmpty() && rootTab.getHiddenApiStorageTab() != null) {
                        List<HiddenEndpoint_littlespidy> epList = new ArrayList<>();
                        for (HiddenEndpointDTO hDto : root.hiddenEndpoints) {
                            HiddenEndpoint_littlespidy ep = deserializeHiddenEndpoint(hDto);
                            if (ep != null) epList.add(ep);
                        }
                        rootTab.getHiddenApiStorageTab().setEndpoints(epList);
                    }

                    // Resync profile selections across tabs
                    rootTab.getImportTab().updateAvailableProfiles(rootTab.getAuthTestingTab().getAllProfiles());
                    rootTab.getAuthTestingTab().refreshCollectionsCombo();

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

    public static ImportedCollectionDTO serializeImportedCollection(ImportedCollection_littlespidy col) {
        if (col == null) return null;
        ImportedCollectionDTO dto = new ImportedCollectionDTO();
        dto.id = col.getId();
        dto.name = col.getName();
        dto.formatType = col.getFormatType();
        dto.sourceType = col.getSourceType();
        dto.sourceLocation = col.getSourceLocation();
        dto.targetBaseUrl = col.getTargetBaseUrl();
        dto.importStatus = col.getImportStatus();
        dto.statusMessage = col.getStatusMessage();
        dto.importedAt = col.getImportedAt();
        dto.assignedProfileId = col.getAssignedProfileId();

        if (col.getEndpoints() != null) {
            for (DiscoveredEndpoint_littlespidy ep : col.getEndpoints()) {
                DiscoveredEndpointDTO epDto = new DiscoveredEndpointDTO();
                epDto.id = ep.getId();
                epDto.method = ep.getMethod();
                epDto.path = ep.getPath();
                epDto.summary = ep.getSummary();
                epDto.description = ep.getDescription();
                epDto.headers = ep.getHeaders();
                epDto.queryParams = ep.getQueryParams();
                epDto.pathParams = ep.getPathParams();
                epDto.bodyParams = ep.getBodyParams();
                epDto.queryParamTypes = ep.getQueryParamTypes();
                epDto.pathParamTypes = ep.getPathParamTypes();
                epDto.bodyParamTypes = ep.getBodyParamTypes();
                epDto.requestBodySample = ep.getRequestBodySample();
                epDto.contentType = ep.getContentType();
                epDto.requiresAuth = ep.isRequiresAuth();
                epDto.authSchemes = ep.getAuthSchemes();
                epDto.customRawRequest = ep.getCustomRawRequest();
                dto.endpoints.add(epDto);
            }
        }
        return dto;
    }

    public static ImportedCollection_littlespidy deserializeImportedCollection(ImportedCollectionDTO dto) {
        if (dto == null) return null;
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy(
                dto.name,
                dto.formatType,
                dto.sourceType,
                dto.sourceLocation
        );
        col.setId(dto.id);
        col.setTargetBaseUrl(dto.targetBaseUrl);
        col.setImportStatus(dto.importStatus);
        col.setStatusMessage(dto.statusMessage);
        col.setImportedAt(dto.importedAt);
        col.setAssignedProfileId(dto.assignedProfileId);

        List<DiscoveredEndpoint_littlespidy> eps = new ArrayList<>();
        if (dto.endpoints != null) {
            for (DiscoveredEndpointDTO epDto : dto.endpoints) {
                DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy(epDto.method, epDto.path, epDto.summary);
                ep.setId(epDto.id);
                ep.setDescription(epDto.description);
                ep.setHeaders(epDto.headers);
                ep.setQueryParams(epDto.queryParams);
                ep.setPathParams(epDto.pathParams);
                if (epDto.bodyParams != null) ep.setBodyParams(epDto.bodyParams);
                if (epDto.queryParamTypes != null) ep.setQueryParamTypes(epDto.queryParamTypes);
                if (epDto.pathParamTypes != null) ep.setPathParamTypes(epDto.pathParamTypes);
                if (epDto.bodyParamTypes != null) ep.setBodyParamTypes(epDto.bodyParamTypes);
                ep.setRequestBodySample(epDto.requestBodySample);
                ep.setContentType(epDto.contentType);
                ep.setRequiresAuth(epDto.requiresAuth);
                ep.setAuthSchemes(epDto.authSchemes);
                ep.setCustomRawRequest(epDto.customRawRequest);
                eps.add(ep);
            }
        }
        col.setEndpoints(eps);
        return col;
    }

    public static AuthProfileDTO serializeAuthProfile(AuthProfile_littlespidy p) {
        if (p == null) return null;
        AuthProfileDTO dto = new AuthProfileDTO();
        dto.id = p.getId();
        dto.name = p.getName();
        dto.authType = p.getAuthType().name();
        dto.bearerToken = p.getBearerToken();
        dto.apiKeyName = p.getApiKeyName();
        dto.apiKeyValue = p.getApiKeyValue();
        dto.apiKeyLocation = p.getApiKeyLocation().name();
        dto.basicUsername = p.getBasicUsername();
        dto.basicPassword = p.getBasicPassword();
        dto.cookieName = p.getCookieName();
        dto.cookieValue = p.getCookieValue();
        dto.customHeaderName = p.getCustomHeaderName();
        dto.customHeaderValue = p.getCustomHeaderValue();
        dto.testUnauthenticatedComparison = p.isTestUnauthenticatedComparison();
        return dto;
    }

    public static AuthProfile_littlespidy deserializeAuthProfile(AuthProfileDTO dto) {
        if (dto == null) return null;
        AuthType_littlespidy at = AuthType_littlespidy.BEARER_TOKEN;
        try {
            if (dto.authType != null) at = AuthType_littlespidy.valueOf(dto.authType);
        } catch (Exception ignored) {}

        AuthProfile_littlespidy p = new AuthProfile_littlespidy(dto.name, at);
        p.setId(dto.id);
        p.setBearerToken(dto.bearerToken);
        p.setApiKeyName(dto.apiKeyName);
        p.setApiKeyValue(dto.apiKeyValue);
        try {
            if (dto.apiKeyLocation != null) p.setApiKeyLocation(ApiKeyLocation_littlespidy.valueOf(dto.apiKeyLocation));
        } catch (Exception ignored) {}
        p.setBasicUsername(dto.basicUsername);
        p.setBasicPassword(dto.basicPassword);
        p.setCookieName(dto.cookieName);
        p.setCookieValue(dto.cookieValue);
        p.setCustomHeaderName(dto.customHeaderName);
        p.setCustomHeaderValue(dto.customHeaderValue);
        p.setTestUnauthenticatedComparison(dto.testUnauthenticatedComparison);
        return p;
    }

    public static AuthTestResultDTO serializeAuthTestResult(AuthTestResult_littlespidy r) {
        if (r == null) return null;
        AuthTestResultDTO dto = new AuthTestResultDTO();
        dto.id = r.getId();
        dto.collectionId = r.getCollectionId();
        dto.collectionName = r.getCollectionName();
        dto.method = r.getMethod();
        dto.path = r.getPath();
        dto.fullUrl = r.getFullUrl();
        dto.profileId = r.getProfileId();
        dto.profileName = r.getProfileName();
        dto.authStatusCode = r.getAuthStatusCode();
        dto.authResponseLength = r.getAuthResponseLength();
        dto.authLatencyMs = r.getAuthLatencyMs();
        dto.unauthStatusCode = r.getUnauthStatusCode();
        dto.unauthResponseLength = r.getUnauthResponseLength();
        dto.unauthLatencyMs = r.getUnauthLatencyMs();
        dto.outcome = r.getOutcome().name();
        dto.errorMessage = r.getErrorMessage();
        dto.timestamp = r.getTimestamp();
        if (r.getAuthRequestBytes() != null) {
            dto.authRequestBase64 = Base64.getEncoder().encodeToString(r.getAuthRequestBytes());
        }
        if (r.getAuthResponseBytes() != null) {
            dto.authResponseBase64 = Base64.getEncoder().encodeToString(r.getAuthResponseBytes());
        }
        if (r.getUnauthRequestBytes() != null) {
            dto.unauthRequestBase64 = Base64.getEncoder().encodeToString(r.getUnauthRequestBytes());
        }
        if (r.getUnauthResponseBytes() != null) {
            dto.unauthResponseBase64 = Base64.getEncoder().encodeToString(r.getUnauthResponseBytes());
        }
        return dto;
    }

    public static AuthTestResult_littlespidy deserializeAuthTestResult(AuthTestResultDTO dto) {
        if (dto == null) return null;
        AuthTestResult_littlespidy r = new AuthTestResult_littlespidy();
        r.setId(dto.id);
        r.setCollectionId(dto.collectionId);
        r.setCollectionName(dto.collectionName);
        r.setMethod(dto.method);
        r.setPath(dto.path);
        r.setFullUrl(dto.fullUrl);
        r.setProfileId(dto.profileId);
        r.setProfileName(dto.profileName);
        r.setAuthStatusCode(dto.authStatusCode);
        r.setAuthResponseLength(dto.authResponseLength);
        r.setAuthLatencyMs(dto.authLatencyMs);
        r.setUnauthStatusCode(dto.unauthStatusCode);
        r.setUnauthResponseLength(dto.unauthResponseLength);
        r.setUnauthLatencyMs(dto.unauthLatencyMs);
        try {
            if (dto.outcome != null) r.setOutcome(AuthTestOutcome_littlespidy.valueOf(dto.outcome));
        } catch (Exception ignored) {}
        r.setErrorMessage(dto.errorMessage);
        r.setTimestamp(dto.timestamp);
        if (dto.authRequestBase64 != null) {
            r.setAuthRequestBytes(Base64.getDecoder().decode(dto.authRequestBase64));
        }
        if (dto.authResponseBase64 != null) {
            r.setAuthResponseBytes(Base64.getDecoder().decode(dto.authResponseBase64));
        }
        if (dto.unauthRequestBase64 != null) {
            r.setUnauthRequestBytes(Base64.getDecoder().decode(dto.unauthRequestBase64));
        }
        if (dto.unauthResponseBase64 != null) {
            r.setUnauthResponseBytes(Base64.getDecoder().decode(dto.unauthResponseBase64));
        }
        return r;
    }

    public static SessionStoreDTO serializeSessionStore(SessionStore_littlespidy s) {
        if (s == null) return null;
        SessionStoreDTO dto = new SessionStoreDTO();
        dto.enabled = s.isEnabled();
        dto.applyMode = s.getApplyMode();
        dto.bearerToken = s.getBearerToken();
        dto.customHeaders = new java.util.LinkedHashMap<>(s.getCustomHeaders());
        dto.cookieName = s.getCookieName();
        dto.cookieValue = s.getCookieValue();
        return dto;
    }

    public static SessionStore_littlespidy deserializeSessionStore(SessionStoreDTO dto) {
        if (dto == null) return new SessionStore_littlespidy();
        SessionStore_littlespidy s = new SessionStore_littlespidy();
        s.setEnabled(dto.enabled);
        s.setApplyMode(dto.applyMode);
        s.setBearerToken(dto.bearerToken);
        if (dto.customHeaders != null) {
            s.setCustomHeaders(dto.customHeaders);
        }
        s.setCookieName(dto.cookieName);
        s.setCookieValue(dto.cookieValue);
        return s;
    }

    public static HiddenEndpointDTO serializeHiddenEndpoint(HiddenEndpoint_littlespidy ep) {
        if (ep == null) return null;
        HiddenEndpointDTO dto = new HiddenEndpointDTO();
        dto.id = ep.getId();
        dto.source = ep.getSource();
        dto.method = ep.getMethod();
        dto.url = ep.getUrl();
        dto.path = ep.getPath();
        dto.parametersSummary = ep.getParametersSummary();
        dto.statusCode = ep.getStatusCode();
        dto.notes = ep.getNotes();
        dto.discoveredAt = ep.getDiscoveredAt();
        if (ep.getRawRequest() != null) {
            dto.request = serializeHttpRequest(ep.getRawRequest());
        }
        if (ep.getRawResponse() != null) {
            dto.response = serializeHttpResponse(ep.getRawResponse(), ep.getRawRequest() != null ? ep.getRawRequest().httpService() : null);
        }
        return dto;
    }

    public static HiddenEndpoint_littlespidy deserializeHiddenEndpoint(HiddenEndpointDTO dto) {
        if (dto == null) return null;
        HiddenEndpoint_littlespidy ep = new HiddenEndpoint_littlespidy();
        if (dto.id != null) ep.setId(dto.id);
        if (dto.source != null) ep.setSource(dto.source);
        if (dto.method != null) ep.setMethod(dto.method);
        if (dto.url != null) ep.setUrl(dto.url);
        if (dto.path != null) ep.setPath(dto.path);
        if (dto.parametersSummary != null) ep.setParametersSummary(dto.parametersSummary);
        ep.setStatusCode(dto.statusCode);
        if (dto.notes != null) ep.setNotes(dto.notes);
        if (dto.discoveredAt > 0) ep.setDiscoveredAt(dto.discoveredAt);
        if (dto.request != null) {
            ep.setRawRequest(deserializeHttpRequest(dto.request));
        }
        if (dto.response != null) {
            ep.setRawResponse(deserializeHttpResponse(dto.response));
        }
        return ep;
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
