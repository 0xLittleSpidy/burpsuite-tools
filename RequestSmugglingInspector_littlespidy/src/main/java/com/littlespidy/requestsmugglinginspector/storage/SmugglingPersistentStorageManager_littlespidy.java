// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.storage;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.requestsmugglinginspector.model.PayloadStore;
import com.littlespidy.requestsmugglinginspector.storage.SmugglingSessionDTO_littlespidy.SessionRootDTO;
import com.littlespidy.requestsmugglinginspector.ui.PayloadsTab;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for Request Smuggling Inspector.
 * Uses plain ASCII text only.
 */
public class SmugglingPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "RequestSmuggling-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private PayloadsTab boundTab = null;
    private PayloadStore boundStore = null;

    private final JLabel sessionStatusLabel;

    public SmugglingPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        this.autoSaveExecutor.scheduleWithFixedDelay(this::autoSaveIfDirty, 30, 30, TimeUnit.SECONDS);
    }

    public void bindTab(PayloadsTab tab) {
        this.boundTab = tab;
    }

    public void bindStore(PayloadStore store) {
        this.boundStore = store;
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

            if (boundStore != null) {
                boundStore.importSessionDTO(root);
            }
            if (boundTab != null) {
                boundTab.refreshTable();
            }

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
        chooser.setDialogTitle("Save Request Smuggling Session As...");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        chooser.setSelectedFile(new File(lastDir, "request_smuggling_session.json"));

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
        chooser.setDialogTitle("Load Request Smuggling Session...");
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
                "Offboarding will unbind the active session file and reset payloads to default bundled values.\n" +
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
            if (boundStore != null) {
                boundStore.reload();
            }
            if (boundTab != null) {
                boundTab.refreshTable();
            }
            updateStatusLabel("Session: [Fresh / Unbound]");
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("Request Smuggling Inspector session offboarded.");
            }
        }
    }

    public void markDirty() {
        this.dirty.set(true);
    }

    public synchronized void saveSessionToFile(File targetFile) {
        if (targetFile == null || boundStore == null) return;
        try {
            SessionRootDTO root = boundStore.exportSessionDTO();
            root.savedAt = Instant.now().toString();
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
                api.logging().logToOutput("Request Smuggling session saved successfully to: " + targetFile.getName());
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
        offboardBtn.setToolTipText("Reset payloads to default and unbind the active session file");
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
