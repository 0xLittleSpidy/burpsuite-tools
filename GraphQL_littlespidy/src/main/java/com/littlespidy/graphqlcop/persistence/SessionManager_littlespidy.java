// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.persistence;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.graphqlcop.model.WorkspaceSessionData_littlespidy;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class SessionManager_littlespidy {

    private final MontoyaApi api;
    private final SessionPersistenceCallback callback;
    private final ScheduledExecutorService autoSaveExecutor;
    private final JLabel sessionStatusLabel;
    private final Gson gson;

    private File activeSessionFile;
    private ScheduledFuture<?> pendingSaveTask;
    private boolean isDirty = false;

    public interface SessionPersistenceCallback {
        WorkspaceSessionData_littlespidy exportCurrentSession();
        void importSession(WorkspaceSessionData_littlespidy data);
        void resetSession();
    }

    public SessionManager_littlespidy(MontoyaApi api, SessionPersistenceCallback callback) {
        this.api = api;
        this.callback = callback;
        this.gson = new GsonBuilder().setPrettyPrinting().create();

        this.sessionStatusLabel = new JLabel("Session: [Temporary / In-Memory]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        this.autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "GraphQL-Session-AutoSave-Thread-littlespidy");
            t.setDaemon(true);
            return t;
        });

        if (api != null && api.extension() != null) {
            api.extension().registerUnloadingHandler(this::handleUnload);
        }
    }

    public void initializeOnStartup(Component parent) {
        SessionStartupDialog_littlespidy.StartupResult result = SessionStartupDialog_littlespidy.promptUser(api, parent);
        switch (result.action()) {
            case OPEN_EXISTING -> openSessionFile(result.sessionFile());
            case CREATE_NEW -> createNewSessionFile(result.sessionFile());
            case TEMPORARY -> startTemporarySession();
        }
    }

    public synchronized void markDirty() {
        this.isDirty = true;
        if (activeSessionFile == null) return;

        if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
            pendingSaveTask.cancel(false);
        }
        pendingSaveTask = autoSaveExecutor.schedule(this::saveSync, 1500, TimeUnit.MILLISECONDS);
    }

    public synchronized void saveSync() {
        if (activeSessionFile == null || !isDirty) return;
        try {
            WorkspaceSessionData_littlespidy data = callback.exportCurrentSession();
            data.setSavedTimestamp(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            String json = gson.toJson(data);

            File tempFile = new File(activeSessionFile.getAbsolutePath() + ".tmp");
            Files.writeString(tempFile.toPath(), json);
            try {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
            isDirty = false;
        } catch (Exception ex) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("Failed to save GraphQL session: " + ex.getMessage());
            }
        }
    }

    public void openSessionFile(File file) {
        if (file == null || !file.exists()) return;
        try {
            String json = Files.readString(file.toPath());
            WorkspaceSessionData_littlespidy data = gson.fromJson(json, WorkspaceSessionData_littlespidy.class);
            callback.importSession(data);
            this.activeSessionFile = file;
            this.isDirty = false;
            updateStatusLabel();
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("GraphQL session loaded: " + file.getAbsolutePath());
            }
        } catch (Exception ex) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("Error loading session file " + file.getAbsolutePath() + ": " + ex.getMessage());
            }
            JOptionPane.showMessageDialog(null, "Error loading session file:\n" + ex.getMessage(), "Session Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void createNewSessionFile(File file) {
        if (file == null) return;
        callback.resetSession();
        this.activeSessionFile = file;
        this.isDirty = true;
        saveSync();
        updateStatusLabel();
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("New GraphQL session created: " + file.getAbsolutePath());
        }
    }

    public void startTemporarySession() {
        callback.resetSession();
        this.activeSessionFile = null;
        this.isDirty = false;
        updateStatusLabel();
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("GraphQL temporary in-memory session started.");
        }
    }

    public void offboardSession(Component parent) {
        if (activeSessionFile != null && isDirty) {
            int res = JOptionPane.showConfirmDialog(parent, "Save changes to active session before offboarding?", "Offboard Session", JOptionPane.YES_NO_CANCEL_OPTION);
            if (res == JOptionPane.YES_OPTION) {
                saveSync();
            } else if (res == JOptionPane.CANCEL_OPTION) {
                return;
            }
        }
        this.activeSessionFile = null;
        this.isDirty = false;
        callback.resetSession();
        updateStatusLabel();
    }

    private void updateStatusLabel() {
        SwingUtilities.invokeLater(() -> {
            if (activeSessionFile != null) {
                sessionStatusLabel.setText("Session: " + activeSessionFile.getName() + " (" + activeSessionFile.getParent() + ")");
                sessionStatusLabel.setToolTipText(activeSessionFile.getAbsolutePath());
            } else {
                sessionStatusLabel.setText("Session: [Temporary / In-Memory]");
                sessionStatusLabel.setToolTipText("Data is in-memory. Use 'Save As...' to bind to a file.");
            }
        });
    }

    public JPanel createSessionToolbarComponent(Component parent) {
        JPanel panel = new JPanel(new BorderLayout(8, 2));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JButton newBtn = new JButton("New Session");
        newBtn.addActionListener(e -> {
            if (isDirty && activeSessionFile != null) {
                int res = JOptionPane.showConfirmDialog(parent, "Save current session before creating a new one?", "Unsaved Changes", JOptionPane.YES_NO_CANCEL_OPTION);
                if (res == JOptionPane.YES_OPTION) saveSync();
                else if (res == JOptionPane.CANCEL_OPTION) return;
            }

            JFileChooser dirChooser = new JFileChooser(getLastDirectory());
            dirChooser.setDialogTitle("Select Directory For New Session");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (dirChooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File dir = dirChooser.getSelectedFile();
                if (api != null && api.persistence() != null) {
                    api.persistence().preferences().setString("graphql_last_session_dir", dir.getAbsolutePath());
                }
                String name = JOptionPane.showInputDialog(parent, "Enter session filename:", "graphql_session.json");
                if (name != null && !name.isBlank()) {
                    if (!name.toLowerCase().endsWith(".json")) name += ".json";
                    createNewSessionFile(new File(dir, name));
                }
            }
        });

        JButton openBtn = new JButton("Open Session");
        openBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(getLastDirectory());
            chooser.setDialogTitle("Select Session File to Open");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
                File sel = chooser.getSelectedFile();
                if (api != null && api.persistence() != null && sel.getParent() != null) {
                    api.persistence().preferences().setString("graphql_last_session_dir", sel.getParent());
                }
                openSessionFile(sel);
            }
        });

        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> {
            if (activeSessionFile != null) {
                isDirty = true;
                saveSync();
                JOptionPane.showMessageDialog(parent, "Session saved successfully.", "Session Saved", JOptionPane.INFORMATION_MESSAGE);
            } else {
                promptSaveAs(parent);
            }
        });

        JButton saveAsBtn = new JButton("Save As...");
        saveAsBtn.addActionListener(e -> promptSaveAs(parent));

        JButton offboardBtn = new JButton("Offboard Session");
        offboardBtn.addActionListener(e -> offboardSession(parent));

        actionsPanel.add(newBtn);
        actionsPanel.add(openBtn);
        actionsPanel.add(saveBtn);
        actionsPanel.add(saveAsBtn);
        actionsPanel.add(offboardBtn);

        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        statusPanel.add(sessionStatusLabel);

        panel.add(actionsPanel, BorderLayout.WEST);
        panel.add(statusPanel, BorderLayout.EAST);
        return panel;
    }

    private void promptSaveAs(Component parent) {
        JFileChooser chooser = new JFileChooser(getLastDirectory());
        chooser.setDialogTitle("Save Session As");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        if (chooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            this.activeSessionFile = sel;
            this.isDirty = true;
            saveSync();
            updateStatusLabel();
            JOptionPane.showMessageDialog(parent, "Session saved as " + sel.getName(), "Session Saved", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private File getLastDirectory() {
        String lastDir = (api != null && api.persistence() != null)
                ? api.persistence().preferences().getString("graphql_last_session_dir")
                : null;
        if (lastDir != null && !lastDir.isBlank()) {
            File dir = new File(lastDir);
            if (dir.exists()) return dir;
        }
        return new File(System.getProperty("user.home"));
    }

    private void handleUnload() {
        if (activeSessionFile != null && isDirty) {
            saveSync();
        }
        autoSaveExecutor.shutdownNow();
    }

    public File getActiveSessionFile() {
        return activeSessionFile;
    }

    public boolean isDirty() {
        return isDirty;
    }
}
