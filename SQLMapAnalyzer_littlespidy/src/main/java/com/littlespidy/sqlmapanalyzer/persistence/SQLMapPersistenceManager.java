// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.persistence;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.sqlmapanalyzer.model.DatabaseModel;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;
import com.littlespidy.sqlmapanalyzer.ui.SQLMapAnalyzerTab;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages session persistence, atomic auto-saves, and state offboarding.
 * Plain ASCII text only.
 */
public class SQLMapPersistenceManager {

    private final MontoyaApi api;
    private final Gson gson;
    private final JLabel sessionStatusLabel;
    private final ScheduledExecutorService autoSaveScheduler;
    private ScheduledFuture<?> pendingSaveTask = null;
    private final AtomicBoolean dirty = new AtomicBoolean(false);

    private volatile File activeSessionFile = null;
    private SQLMapAnalyzerTab mainTab;
    private SqlmapDataStore dataStore;

    public SQLMapPersistenceManager(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.sessionStatusLabel = new JLabel("Session: [Temporary / In-Memory]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        this.autoSaveScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "sqlmap-analyzer-autosave");
            t.setDaemon(true);
            return t;
        });

        if (api != null && api.extension() != null) {
            api.extension().registerUnloadingHandler(this::onExtensionUnload);
        }
    }

    public void bindContext(SQLMapAnalyzerTab mainTab, SqlmapDataStore dataStore) {
        this.mainTab = mainTab;
        this.dataStore = dataStore;
    }

    public JLabel getSessionStatusLabel() {
        return sessionStatusLabel;
    }

    public File getActiveSessionFile() {
        return activeSessionFile;
    }

    public void handleStartupResult(SessionStartupDialog_littlespidy.StartupResult result) {
        if (result == null) return;
        switch (result.action()) {
            case OPEN_EXISTING -> {
                if (result.sessionFile() != null && result.sessionFile().exists()) {
                    loadSession(result.sessionFile(), true);
                }
            }
            case CREATE_NEW -> {
                if (result.sessionFile() != null) {
                    this.activeSessionFile = result.sessionFile();
                    updateStatusLabel();
                    triggerAutoSave();
                }
            }
            case TEMPORARY -> {
                this.activeSessionFile = null;
                updateStatusLabel();
            }
        }
    }

    public synchronized void triggerAutoSave() {
        dirty.set(true);
        if (activeSessionFile == null) return;

        if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
            pendingSaveTask.cancel(false);
        }

        pendingSaveTask = autoSaveScheduler.schedule(() -> {
            performSave(activeSessionFile);
        }, 1500, TimeUnit.MILLISECONDS);
    }

    public synchronized boolean performSave(File destination) {
        if (destination == null || dataStore == null) return false;

        try {
            SQLMapSessionData sessionData = new SQLMapSessionData();
            sessionData.setSqlmapRootDirectory(dataStore.getSqlmapRootPath());
            sessionData.setTimestamp(System.currentTimeMillis());
            sessionData.setDatabases(dataStore.getAllDatabases());
            sessionData.setBookmarks(new ArrayList<>(dataStore.getBookmarks()));
            sessionData.setNotes(dataStore.getNotes());

            if (mainTab != null) {
                sessionData.setSelectedDatabase(mainTab.getSelectedDatabaseName());
                sessionData.setSelectedTable(mainTab.getSelectedTableName());
            }

            File parentDir = destination.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            File tempFile = new File(destination.getAbsolutePath() + ".tmp");
            try (Writer writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8)) {
                gson.toJson(sessionData, writer);
            }

            Files.move(tempFile.toPath(), destination.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            dirty.set(false);
            SwingUtils.runOnEdt(this::updateStatusLabel);
            return true;
        } catch (Exception e) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("Error saving session: " + e.getMessage());
            }
            return false;
        }
    }

    public boolean loadSession(File file, boolean showConfirmationDialog) {
        if (file == null || !file.exists() || dataStore == null) return false;

        try (Reader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            SQLMapSessionData data = gson.fromJson(reader, SQLMapSessionData.class);
            if (data == null) return false;

            dataStore.clear();
            dataStore.setSqlmapRootPath(data.getSqlmapRootDirectory());
            if (data.getDatabases() != null) {
                for (DatabaseModel db : data.getDatabases()) {
                    dataStore.addDatabase(db);
                }
            }
            dataStore.rebuildColumnIndex();

            if (data.getBookmarks() != null) {
                for (String b : data.getBookmarks()) {
                    dataStore.addBookmark(b);
                }
            }
            if (data.getNotes() != null) {
                for (var entry : data.getNotes().entrySet()) {
                    dataStore.setNote(entry.getKey(), entry.getValue());
                }
            }

            this.activeSessionFile = file;
            dirty.set(false);

            SwingUtils.runOnEdt(() -> {
                updateStatusLabel();
                if (mainTab != null) {
                    mainTab.refreshFromDataStore();
                    if (data.getSelectedDatabase() != null && !data.getSelectedDatabase().isBlank()) {
                        mainTab.selectDatabaseAndTable(data.getSelectedDatabase(), data.getSelectedTable());
                    }
                }
                if (showConfirmationDialog && mainTab != null) {
                    JOptionPane.showMessageDialog(mainTab,
                            "Session loaded successfully.\nDatabases: " + dataStore.getAllDatabases().size() +
                                    "\nTables: " + dataStore.getAllTables().size(),
                            "Session Loaded", JOptionPane.INFORMATION_MESSAGE);
                }
            });

            return true;
        } catch (Exception e) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("Failed to load session: " + e.getMessage());
            }
            JOptionPane.showMessageDialog(mainTab, "Failed to load session: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    public void createNewSession(Component parent) {
        JFileChooser chooser = new JFileChooser(getStartingDirectory());
        chooser.setDialogTitle("Select Directory for New Session");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int res = chooser.showOpenDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File dir = chooser.getSelectedFile();
            String fileName = JOptionPane.showInputDialog(parent, "Enter session filename:", "sqlmap_session.json");
            if (fileName != null && !fileName.isBlank()) {
                if (!fileName.toLowerCase().endsWith(".json")) {
                    fileName = fileName + ".json";
                }
                File sessionFile = new File(dir, fileName.trim());
                this.activeSessionFile = sessionFile;
                updateStatusLabel();
                performSave(sessionFile);
                JOptionPane.showMessageDialog(parent, "New session created and bound to:\n" + sessionFile.getAbsolutePath(),
                        "New Session Bound", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    public void openSession(Component parent) {
        JFileChooser chooser = new JFileChooser(getStartingDirectory());
        chooser.setDialogTitle("Open SQLMap Session File");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        int res = chooser.showOpenDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            loadSession(chooser.getSelectedFile(), true);
        }
    }

    public void saveSession(Component parent) {
        if (activeSessionFile != null) {
            if (performSave(activeSessionFile)) {
                showSafeMessageDialog(parent, "Session saved successfully to:\n" + activeSessionFile.getAbsolutePath(),
                        "Session Saved", JOptionPane.INFORMATION_MESSAGE);
            }
        } else {
            saveSessionAs(parent);
        }
    }

    public void saveSessionAs(Component parent) {
        if (GraphicsEnvironment.isHeadless() || Boolean.getBoolean("java.awt.headless")) return;
        JFileChooser chooser = new JFileChooser(getStartingDirectory());
        chooser.setDialogTitle("Save Session As");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        chooser.setSelectedFile(new File(getStartingDirectory(), "sqlmap_session.json"));
        int res = chooser.showSaveDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            if (performSave(sel)) {
                this.activeSessionFile = sel;
                updateStatusLabel();
                showSafeMessageDialog(parent, "Session saved successfully to:\n" + sel.getAbsolutePath(),
                        "Session Saved", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void showSafeMessageDialog(Component parent, String message, String title, int messageType) {
        if (!GraphicsEnvironment.isHeadless() && !Boolean.getBoolean("java.awt.headless") && parent != null && parent.isShowing()) {
            JOptionPane.showMessageDialog(parent, message, title, messageType);
        }
    }

    public void offboardSession(Component parent) {
        if (dirty.get() && activeSessionFile != null) {
            int prompt = JOptionPane.showConfirmDialog(parent,
                    "There are unsaved changes in the active session. Would you like to save before offboarding?",
                    "Save Before Offboard", JOptionPane.YES_NO_CANCEL_OPTION);
            if (prompt == JOptionPane.CANCEL_OPTION) {
                return;
            }
            if (prompt == JOptionPane.YES_OPTION) {
                performSave(activeSessionFile);
            }
        }

        this.activeSessionFile = null;
        this.dirty.set(false);
        if (dataStore != null) {
            dataStore.clear();
        }
        SwingUtils.runOnEdt(() -> {
            updateStatusLabel();
            if (mainTab != null) {
                mainTab.clearViews();
            }
        });

        JOptionPane.showMessageDialog(parent, "Session offboarded. Workspace cleared to clean state.",
                "Session Offboarded", JOptionPane.INFORMATION_MESSAGE);
    }

    private void updateStatusLabel() {
        if (activeSessionFile != null) {
            String dirtyMarker = dirty.get() ? " *" : "";
            sessionStatusLabel.setText("Session: " + activeSessionFile.getName() + " (" + activeSessionFile.getParent() + ")" + dirtyMarker);
        } else {
            sessionStatusLabel.setText("Session: [Temporary / In-Memory]");
        }
    }

    private File getStartingDirectory() {
        if (activeSessionFile != null && activeSessionFile.getParentFile() != null) {
            return activeSessionFile.getParentFile();
        }
        return new File(System.getProperty("user.home", "."));
    }

    private void onExtensionUnload() {
        if (activeSessionFile != null && dirty.get()) {
            performSave(activeSessionFile);
        }
        autoSaveScheduler.shutdown();
    }
}
