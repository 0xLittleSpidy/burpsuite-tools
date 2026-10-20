// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.storage;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.payloadinjector.model.*;
import com.littlespidy.payloadinjector.storage.PayloadInjectorSessionDTO_littlespidy.*;
import com.littlespidy.payloadinjector.ui.PayloadInjectorTab;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for Payload Injector.
 * Uses plain ASCII text only.
 */
public class PayloadInjectorPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "PayloadInjector-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);

    private PayloadInjectorTab boundTab;
    private Map<String, ParamPayloadStore> paramStores;
    private SmugglingPayloadStore smugglingStore;
    private FilePathStore_littlespidy linuxFilePathStore;
    private FilePathStore_littlespidy windowsFilePathStore;
    private InjectionSettings settings;

    private final JLabel sessionStatusLabel;

    public PayloadInjectorPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        this.autoSaveExecutor.scheduleWithFixedDelay(this::autoSaveIfDirty, 30, 30, TimeUnit.SECONDS);
    }

    public void bindContext(PayloadInjectorTab tab,
                            Map<String, ParamPayloadStore> paramStores,
                            SmugglingPayloadStore smugglingStore,
                            FilePathStore_littlespidy linuxFilePathStore,
                            FilePathStore_littlespidy windowsFilePathStore,
                            InjectionSettings settings) {
        this.boundTab = tab;
        this.paramStores = paramStores;
        this.smugglingStore = smugglingStore;
        this.linuxFilePathStore = linuxFilePathStore;
        this.windowsFilePathStore = windowsFilePathStore;
        this.settings = settings;

        if (this.settings != null) {
            this.settings.addChangeListener(this::markDirty);
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
        chooser.setDialogTitle("Save Payload Injector Session As...");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        chooser.setSelectedFile(new File(lastDir, "payload_injector_session.json"));

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
        chooser.setDialogTitle("Load Payload Injector Session...");
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
                "Offboarding will unbind the active session file and reload all payloads from their default JSON files.\n" +
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

            // Reload default payloads from disk
            if (paramStores != null) {
                for (ParamPayloadStore store : paramStores.values()) {
                    store.reload();
                }
            }
            if (smugglingStore != null) {
                smugglingStore.reload();
            }
            if (linuxFilePathStore != null) {
                linuxFilePathStore.reload();
            }
            if (windowsFilePathStore != null) {
                windowsFilePathStore.reload();
            }
            if (settings != null) {
                settings.setInjectionMode(InjectionSettings.InjectionMode.REPLACE);
                settings.setEncodingMode(InjectionSettings.EncodingMode.AUTO);
                settings.setTargetUrlParams(true);
                settings.setTargetBodyParams(true);
                settings.setTargetJsonParams(true);
                settings.setTargetCookieParams(false);
            }

            updateStatusLabel("Session: [Fresh / Unbound]");
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("Payload Injector session offboarded.");
            }
        }
    }

    public void markDirty() {
        this.dirty.set(true);
    }

    public synchronized SessionRootDTO exportSessionDTO() {
        SessionRootDTO root = new SessionRootDTO();
        root.savedAt = Instant.now().toString();

        if (settings != null) {
            root.injectionMode = settings.getInjectionMode() != null ? settings.getInjectionMode().getDisplay() : "";
            root.encodingMode = settings.getEncodingMode() != null ? settings.getEncodingMode().getDisplay() : "";
            root.targetUrlParams = settings.isTargetUrlParams();
            root.targetBodyParams = settings.isTargetBodyParams();
            root.targetJsonParams = settings.isTargetJsonParams();
            root.targetCookieParams = settings.isTargetCookieParams();
        }

        if (paramStores != null) {
            for (Map.Entry<String, ParamPayloadStore> entry : paramStores.entrySet()) {
                List<ParamPayloadDTO> dtoList = new ArrayList<>();
                for (ParamPayloadEntry p : entry.getValue().getEntries()) {
                    ParamPayloadDTO pdto = new ParamPayloadDTO();
                    pdto.id = p.getId();
                    pdto.name = p.getName();
                    pdto.template = p.getTemplate();
                    pdto.description = p.getDescription();
                    pdto.enabled = p.isEnabled();
                    pdto.sourceType = p.getSourceType();
                    pdto.sourceFile = p.getSourceFile();
                    pdto.platform = p.getPlatform();
                    dtoList.add(pdto);
                }
                root.paramPayloads.put(entry.getKey(), dtoList);
            }
        }

        if (smugglingStore != null) {
            for (SmugglingPayloadEntry s : smugglingStore.getEntries()) {
                SmugglingPayloadDTO sdto = new SmugglingPayloadDTO();
                sdto.name = s.getName();
                sdto.description = s.getDescription();
                sdto.headers = new LinkedHashMap<>(s.getHeaders());
                sdto.body = s.getBody();
                sdto.sourceType = s.getSourceType();
                sdto.sourceFile = s.getSourceFile();
                root.smugglingPayloads.add(sdto);
            }
        }

        if (linuxFilePathStore != null) {
            for (FilePathEntry_littlespidy f : linuxFilePathStore.getEntries()) {
                root.linuxFilePaths.add(convertFilePathToDTO(f));
            }
        }

        if (windowsFilePathStore != null) {
            for (FilePathEntry_littlespidy f : windowsFilePathStore.getEntries()) {
                root.windowsFilePaths.add(convertFilePathToDTO(f));
            }
        }

        return root;
    }

    private FilePathDTO convertFilePathToDTO(FilePathEntry_littlespidy f) {
        FilePathDTO dto = new FilePathDTO();
        dto.id = f.getId();
        dto.path = f.getPath();
        dto.category = f.getCategory();
        dto.description = f.getDescription();
        dto.platform = f.getPlatform();
        dto.enabled = f.isEnabled();
        dto.sourceType = f.getSourceType();
        dto.sourceFile = f.getSourceFile();
        return dto;
    }

    public synchronized void restoreFromDTO(SessionRootDTO root) {
        if (root == null) return;

        if (settings != null) {
            for (InjectionSettings.InjectionMode m : InjectionSettings.InjectionMode.values()) {
                if (m.getDisplay().equalsIgnoreCase(root.injectionMode)) {
                    settings.setInjectionMode(m);
                    break;
                }
            }
            for (InjectionSettings.EncodingMode em : InjectionSettings.EncodingMode.values()) {
                if (em.getDisplay().equalsIgnoreCase(root.encodingMode)) {
                    settings.setEncodingMode(em);
                    break;
                }
            }
            settings.setTargetUrlParams(root.targetUrlParams);
            settings.setTargetBodyParams(root.targetBodyParams);
            settings.setTargetJsonParams(root.targetJsonParams);
            settings.setTargetCookieParams(root.targetCookieParams);
        }

        if (paramStores != null && root.paramPayloads != null) {
            for (Map.Entry<String, List<ParamPayloadDTO>> entry : root.paramPayloads.entrySet()) {
                ParamPayloadStore store = paramStores.get(entry.getKey());
                if (store != null) {
                    List<ParamPayloadEntry> list = new ArrayList<>();
                    for (ParamPayloadDTO pdto : entry.getValue()) {
                        list.add(new ParamPayloadEntry(
                                pdto.id,
                                pdto.name,
                                pdto.template,
                                pdto.description,
                                pdto.enabled,
                                pdto.sourceType,
                                pdto.sourceFile,
                                pdto.platform
                        ));
                    }
                    store.replaceEntries(list);
                }
            }
        }

        if (smugglingStore != null && root.smugglingPayloads != null) {
            List<SmugglingPayloadEntry> list = new ArrayList<>();
            for (SmugglingPayloadDTO sdto : root.smugglingPayloads) {
                list.add(new SmugglingPayloadEntry(
                        sdto.name,
                        sdto.description,
                        sdto.headers,
                        sdto.body,
                        sdto.sourceType,
                        sdto.sourceFile
                ));
            }
            smugglingStore.replaceEntries(list);
        }

        if (linuxFilePathStore != null && root.linuxFilePaths != null) {
            List<FilePathEntry_littlespidy> list = new ArrayList<>();
            for (FilePathDTO fdto : root.linuxFilePaths) {
                list.add(new FilePathEntry_littlespidy(
                        fdto.id,
                        fdto.path,
                        fdto.category,
                        fdto.description,
                        fdto.platform,
                        fdto.enabled,
                        fdto.sourceType,
                        fdto.sourceFile
                ));
            }
            linuxFilePathStore.replaceEntries(list);
        }

        if (windowsFilePathStore != null && root.windowsFilePaths != null) {
            List<FilePathEntry_littlespidy> list = new ArrayList<>();
            for (FilePathDTO fdto : root.windowsFilePaths) {
                list.add(new FilePathEntry_littlespidy(
                        fdto.id,
                        fdto.path,
                        fdto.category,
                        fdto.description,
                        fdto.platform,
                        fdto.enabled,
                        fdto.sourceType,
                        fdto.sourceFile
                ));
            }
            windowsFilePathStore.replaceEntries(list);
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
                api.logging().logToOutput("Payload Injector session saved successfully to: " + targetFile.getName());
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
