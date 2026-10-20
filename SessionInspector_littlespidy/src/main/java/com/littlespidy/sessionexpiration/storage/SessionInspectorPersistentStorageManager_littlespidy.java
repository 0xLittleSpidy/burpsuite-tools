// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.storage;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.sessionexpiration.cookiefinder.SessionCookieFinderTab;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieStoreDataStore;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import com.littlespidy.sessionexpiration.persistence.SessionInspectorPersistence;
import com.littlespidy.sessionexpiration.ui.SessionExpirationTab;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for Session Inspector.
 * Plain ASCII text only.
 */
public class SessionInspectorPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "SessionInspector-AutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);

    private SessionExpirationTab boundTab;
    private SessionDataStore boundDataStore;
    private CookieStoreDataStore boundCookieStore;
    private SessionCookieFinderTab boundFinderTab;

    private final JLabel sessionStatusLabel;

    public SessionInspectorPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        this.autoSaveExecutor.scheduleWithFixedDelay(this::autoSaveIfDirty, 30, 30, TimeUnit.SECONDS);
    }

    public void bindContext(SessionExpirationTab tab, SessionDataStore dataStore,
                            CookieStoreDataStore cookieStore, SessionCookieFinderTab finderTab) {
        this.boundTab = tab;
        this.boundDataStore = dataStore;
        this.boundCookieStore = cookieStore;
        this.boundFinderTab = finderTab;
    }

    public void markDirty() {
        dirty.set(true);
    }

    private synchronized void autoSaveIfDirty() {
        if (activeSessionFile != null && dirty.compareAndSet(true, false)) {
            try {
                SessionInspectorPersistence.saveSync(boundDataStore, boundCookieStore, boundFinderTab, activeSessionFile.toPath());
            } catch (Exception e) {
                dirty.set(true);
            }
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
            SessionInspectorPersistence.setActiveSessionFilePath(file.toPath());
            String summary = SessionInspectorPersistence.load(boundDataStore, boundCookieStore, boundFinderTab, api, file.toPath());

            this.activeSessionFile = file;
            this.dirty.set(false);
            updateStatusLabel("Session: " + file.getName() + " (Auto-save Enabled)");
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("Successfully loaded session from: " + file.getAbsolutePath() + " (" + summary + ")");
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
            SessionInspectorPersistence.setActiveSessionFilePath(file.toPath());
            SessionInspectorPersistence.saveSync(boundDataStore, boundCookieStore, boundFinderTab, file.toPath());
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
        SessionInspectorPersistence.setActiveSessionFilePath(null);
        this.dirty.set(false);
        updateStatusLabel("Session: [In-Memory / Temporary]");
    }

    public synchronized void saveActiveSession() {
        if (activeSessionFile != null) {
            saveSessionToFile(activeSessionFile);
            updateStatusLabel("Session: " + activeSessionFile.getName() + " (Auto-save Enabled)");
        } else {
            saveAsSession(boundTab);
        }
    }

    public synchronized void saveSessionToFile(File file) {
        if (file == null) return;
        SessionInspectorPersistence.saveSync(boundDataStore, boundCookieStore, boundFinderTab, file.toPath());
        this.dirty.set(false);
    }

    public synchronized void saveAsSession(Component parent) {
        File lastDir = getLastDirectory();
        JFileChooser chooser = new JFileChooser(lastDir);
        chooser.setDialogTitle("Save Session Inspector Session As...");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        chooser.setSelectedFile(new File(lastDir, "session_inspector_session.json"));

        int res = chooser.showSaveDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            rememberDirectory(sel.getParent());
            this.activeSessionFile = sel;
            SessionInspectorPersistence.setActiveSessionFilePath(sel.toPath());
            SessionInspectorPersistence.saveSync(boundDataStore, boundCookieStore, boundFinderTab, sel.toPath());
            this.dirty.set(false);
            updateStatusLabel("Session: " + sel.getName() + " (Auto-save Enabled)");
            if (!GraphicsEnvironment.isHeadless()) {
                JOptionPane.showMessageDialog(parent, "Session saved successfully to:\n" + sel.getAbsolutePath(),
                        "Session Saved", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    public synchronized void loadSessionPrompt(Component parent) {
        File lastDir = getLastDirectory();
        JFileChooser chooser = new JFileChooser(lastDir);
        chooser.setDialogTitle("Open Session Inspector Session File");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));

        int res = chooser.showOpenDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            rememberDirectory(sel.getParent());
            openSessionFile(sel);
            if (boundTab != null) {
                boundTab.refreshAllTabs();
            }
        }
    }

    public synchronized void offboardSession(Component parent) {
        if (!GraphicsEnvironment.isHeadless()) {
            int confirm = JOptionPane.showConfirmDialog(
                    parent,
                    "Offboarding will save pending changes to the active session (if any),\n" +
                            "reset all monitors, cookie store, and findings to a completely fresh state,\n" +
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

        if (activeSessionFile != null) {
            try {
                SessionInspectorPersistence.saveSync(boundDataStore, boundCookieStore, boundFinderTab, activeSessionFile.toPath());
            } catch (Exception ignored) {}
        }

        if (boundDataStore != null) {
            boundDataStore.clearAll();
        }
        if (boundCookieStore != null) {
            boundCookieStore.clear();
        }
        if (boundFinderTab != null) {
            boundFinderTab.clearAll();
        }

        this.activeSessionFile = null;
        SessionInspectorPersistence.setActiveSessionFilePath(null);
        this.dirty.set(false);
        updateStatusLabel("Session: [In-Memory / Temporary]");

        if (boundTab != null) {
            boundTab.refreshAllTabs();
        }

        if (!GraphicsEnvironment.isHeadless()) {
            JOptionPane.showMessageDialog(
                    parent,
                    "Session successfully offboarded.\nAll monitors and data have been reset to a clean state.",
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
                String name = JOptionPane.showInputDialog(bar, "Enter session filename:", "session_inspector_session.json");
                if (name != null && !name.isBlank()) {
                    if (!name.toLowerCase().endsWith(".json")) name = name + ".json";
                    createNewSessionFile(new File(dir, name.trim()));
                    if (boundTab != null) boundTab.refreshAllTabs();
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
        offboardBtn.setToolTipText("Reset monitors and unbind the active session file");
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
        if (activeSessionFile != null) {
            try {
                SessionInspectorPersistence.saveSync(boundDataStore, boundCookieStore, boundFinderTab, activeSessionFile.toPath());
            } catch (Exception ignored) {}
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
