// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.jssourcemapexplorer.model.*;
import com.littlespidy.jssourcemapexplorer.storage.JsSessionDTO_littlespidy.JsFileDTO;
import com.littlespidy.jssourcemapexplorer.storage.JsSessionDTO_littlespidy.SessionRootDTO;
import com.littlespidy.jssourcemapexplorer.storage.JsSessionDTO_littlespidy.UnpackedProjectDTO;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for JavaScript Inspector.
 */
public class JsPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "JsInspector-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private ScheduledFuture<?> scheduledSaveTask = null;
    private JsDataStore boundDataStore = null;

    private final JLabel sessionStatusLabel;

    public JsPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    }

    public void bindDataStore(JsDataStore dataStore) {
        this.boundDataStore = dataStore;
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

            if (boundDataStore != null) {
                boundDataStore.clear();
                List<JsFileEntry> restoredEntries = new ArrayList<>();
                int maxId = 0;

                if (root.files != null) {
                    for (JsFileDTO dto : root.files) {
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

                        HttpRequest mapReq = null;
                        if (dto.hasSourceMapRequest && dto.sourceMapRequestBase64 != null && !dto.sourceMapRequestBase64.isEmpty()) {
                            try {
                                byte[] mapReqBytes = Base64.getDecoder().decode(dto.sourceMapRequestBase64);
                                HttpService svc = (dto.sourceMapRequestHost != null && !dto.sourceMapRequestHost.isBlank())
                                        ? HttpService.httpService(dto.sourceMapRequestHost, dto.sourceMapRequestPort > 0 ? dto.sourceMapRequestPort : (dto.sourceMapRequestSecure ? 443 : 80), dto.sourceMapRequestSecure)
                                        : null;
                                ByteArray ba = ByteArray.byteArray(mapReqBytes);
                                mapReq = (svc != null) ? HttpRequest.httpRequest(svc, ba) : HttpRequest.httpRequest(ba);
                            } catch (Exception ignored) {}
                        }

                        HttpResponse mapResp = null;
                        if (dto.hasSourceMapResponse && dto.sourceMapResponseBase64 != null && !dto.sourceMapResponseBase64.isEmpty()) {
                            try {
                                byte[] mapRespBytes = Base64.getDecoder().decode(dto.sourceMapResponseBase64);
                                mapResp = HttpResponse.httpResponse(ByteArray.byteArray(mapRespBytes));
                            } catch (Exception ignored) {}
                        }

                        ZonedDateTime ts = null;
                        if (dto.timestamp != null && !dto.timestamp.isBlank()) {
                            try {
                                ts = ZonedDateTime.parse(dto.timestamp);
                            } catch (Exception ignored) {}
                        }
                        if (ts == null) {
                            ts = ZonedDateTime.now();
                        }

                        PassiveMapStatus passiveStatus = PassiveMapStatus.NOT_FOUND;
                        if (dto.passiveMapStatus != null) {
                            try {
                                passiveStatus = PassiveMapStatus.valueOf(dto.passiveMapStatus);
                            } catch (Exception ignored) {}
                        }

                        ActiveProbeStatus activeStatus = ActiveProbeStatus.NOT_RUN;
                        if (dto.activeProbeStatus != null) {
                            try {
                                activeStatus = ActiveProbeStatus.valueOf(dto.activeProbeStatus);
                            } catch (Exception ignored) {}
                        }

                        JsFileEntry entry = new JsFileEntry(
                                dto.id,
                                dto.url,
                                dto.host,
                                dto.path,
                                dto.statusCode,
                                dto.contentLength,
                                dto.firstParty,
                                dto.originLabel,
                                passiveStatus,
                                dto.sourceMapLocation,
                                req,
                                resp,
                                ts
                        );
                        entry.setActiveProbeStatus(activeStatus);
                        if (dto.framework != null) {
                            entry.setFramework(dto.framework);
                        }
                        if (mapReq != null) {
                            entry.setSourceMapRequest(mapReq);
                        }
                        if (mapResp != null) {
                            entry.setSourceMapResponse(mapResp);
                        }

                        entry.setJsReconFindings(
                                dto.secrets,
                                dto.endpoints,
                                dto.cloudUrls,
                                dto.dependencies,
                                dto.comments,
                                dto.securityBypasses,
                                dto.graphQLOperations
                        );

                        if (dto.unpacked && dto.unpackedProject != null) {
                            UnpackedProject project = new UnpackedProject(dto.unpackedProject.sourceMapUrl);
                            if (dto.unpackedProject.files != null) {
                                for (UnpackedSourceFile f : dto.unpackedProject.files) {
                                    project.addFile(f);
                                }
                            }
                            entry.setUnpackedProject(project);
                        }

                        restoredEntries.add(entry);
                        if (dto.id > maxId) {
                            maxId = dto.id;
                        }
                    }
                }

                boundDataStore.addEntries(restoredEntries);
                boundDataStore.setNextId(maxId + 1);
            }

            this.activeSessionFile = file;
            this.dirty.set(false);
            updateStatusLabel();
            log("[JavaScript Inspector] Session opened successfully from: " + file.getAbsolutePath());
        } catch (Exception ex) {
            logError("[JavaScript Inspector] Failed to open session from " + file.getAbsolutePath() + ": " + ex.getMessage());
            JOptionPane.showMessageDialog(null, "Failed to load session file:\n" + ex.getMessage(), "Session Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public synchronized void createNewSessionFile(File file) {
        if (file == null) return;
        if (boundDataStore != null) {
            boundDataStore.clear();
        }
        this.activeSessionFile = file;
        this.dirty.set(true);
        saveNow();
        updateStatusLabel();
        log("[JavaScript Inspector] Created new session bound to: " + file.getAbsolutePath());
    }

    public synchronized void startTemporarySession() {
        if (boundDataStore != null) {
            boundDataStore.clear();
        }
        this.activeSessionFile = null;
        this.dirty.set(false);
        updateStatusLabel();
        log("[JavaScript Inspector] Started temporary in-memory session.");
    }

    public synchronized void offboardSession(Component parent, Runnable onRefresh) {
        if (activeSessionFile == null) {
            if (boundDataStore != null) {
                boundDataStore.clear();
            }
            if (onRefresh != null) SwingUtilities.invokeLater(onRefresh);
            return;
        }

        if (dirty.get()) {
            int choice = JOptionPane.showConfirmDialog(
                    parent,
                    "Save pending changes to active session before offboarding?",
                    "Offboard Session - Unsaved Changes",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (choice == JOptionPane.CANCEL_OPTION) {
                return;
            }
            if (choice == JOptionPane.YES_OPTION) {
                saveNow();
            }
        }

        if (scheduledSaveTask != null) {
            scheduledSaveTask.cancel(false);
            scheduledSaveTask = null;
        }

        File previousFile = this.activeSessionFile;
        this.activeSessionFile = null;
        this.dirty.set(false);

        if (boundDataStore != null) {
            boundDataStore.clear();
        }

        updateStatusLabel();
        if (onRefresh != null) {
            SwingUtilities.invokeLater(onRefresh);
        }
        log("[JavaScript Inspector] Offboarded session " + (previousFile != null ? previousFile.getName() : "") + ". Restored fresh clean state.");
    }

    public void scheduleAutoSave() {
        this.dirty.set(true);
        if (activeSessionFile == null) return;

        synchronized (this) {
            if (scheduledSaveTask != null && !scheduledSaveTask.isDone()) {
                scheduledSaveTask.cancel(false);
            }
            scheduledSaveTask = autoSaveExecutor.schedule(this::saveNow, 1500, TimeUnit.MILLISECONDS);
        }
    }

    public synchronized void saveNow() {
        if (activeSessionFile == null) return;
        try {
            SessionRootDTO root = new SessionRootDTO();
            root.savedAt = Instant.now().toString();

            if (boundDataStore != null) {
                for (JsFileEntry e : boundDataStore.getEntries()) {
                    JsFileDTO dto = new JsFileDTO();
                    dto.id = e.getId();
                    dto.url = e.getUrl();
                    dto.host = e.getHost();
                    dto.path = e.getPath();
                    dto.statusCode = e.getStatusCode();
                    dto.contentLength = e.getContentLength();
                    dto.firstParty = e.isFirstParty();
                    dto.originLabel = e.getOriginLabel();
                    dto.framework = e.getFramework();
                    dto.passiveMapStatus = e.getPassiveMapStatus() != null ? e.getPassiveMapStatus().name() : null;
                    dto.activeProbeStatus = e.getActiveProbeStatus() != null ? e.getActiveProbeStatus().name() : null;
                    dto.unpacked = e.isUnpacked();
                    dto.sourceMapLocation = e.getSourceMapLocation();
                    dto.timestamp = e.getTimestamp() != null ? e.getTimestamp().toString() : "";

                    // Raw HTTP preservation for JS
                    if (e.getRequest() != null) {
                        dto.hasRequest = true;
                        dto.requestBase64 = Base64.getEncoder().encodeToString(e.getRequest().toByteArray().getBytes());
                        if (e.getRequest().httpService() != null) {
                            dto.requestHost = e.getRequest().httpService().host();
                            dto.requestPort = e.getRequest().httpService().port();
                            dto.requestSecure = e.getRequest().httpService().secure();
                        }
                    }

                    if (e.getResponse() != null) {
                        dto.hasResponse = true;
                        dto.responseBase64 = Base64.getEncoder().encodeToString(e.getResponse().toByteArray().getBytes());
                    }

                    // Raw HTTP preservation for Source Map
                    if (e.getSourceMapRequest() != null) {
                        dto.hasSourceMapRequest = true;
                        dto.sourceMapRequestBase64 = Base64.getEncoder().encodeToString(e.getSourceMapRequest().toByteArray().getBytes());
                        if (e.getSourceMapRequest().httpService() != null) {
                            dto.sourceMapRequestHost = e.getSourceMapRequest().httpService().host();
                            dto.sourceMapRequestPort = e.getSourceMapRequest().httpService().port();
                            dto.sourceMapRequestSecure = e.getSourceMapRequest().httpService().secure();
                        }
                    }

                    if (e.getSourceMapResponse() != null) {
                        dto.hasSourceMapResponse = true;
                        dto.sourceMapResponseBase64 = Base64.getEncoder().encodeToString(e.getSourceMapResponse().toByteArray().getBytes());
                    }

                    // Discovered JS Recon Findings
                    dto.secrets = new ArrayList<>(e.getJsSecrets());
                    dto.endpoints = new ArrayList<>(e.getJsEndpoints());
                    dto.cloudUrls = new ArrayList<>(e.getJsCloudUrls());
                    dto.dependencies = new ArrayList<>(e.getJsDependencies());
                    dto.comments = new ArrayList<>(e.getJsComments());
                    dto.securityBypasses = new ArrayList<>(e.getJsSecurityBypasses());
                    dto.graphQLOperations = new ArrayList<>(e.getJsGraphQLOperations());

                    // Unpacked project files
                    if (e.isUnpacked() && e.getUnpackedProject() != null) {
                        UnpackedProjectDTO upDto = new UnpackedProjectDTO();
                        upDto.sourceMapUrl = e.getUnpackedProject().getSourceMapUrl();
                        upDto.files = new ArrayList<>(e.getUnpackedProject().getFiles());
                        dto.unpackedProject = upDto;
                    }

                    root.files.add(dto);
                }
            }

            String json = gson.toJson(root);
            File parentDir = activeSessionFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            File tempFile = new File(activeSessionFile.getAbsolutePath() + ".tmp");
            Files.writeString(tempFile.toPath(), json, StandardCharsets.UTF_8);
            try {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.move(tempFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }

            dirty.set(false);
            updateStatusLabel();
        } catch (Exception ex) {
            logError("[JavaScript Inspector] Error saving session to " + activeSessionFile.getAbsolutePath() + ": " + ex.getMessage());
        }
    }

    public synchronized void saveAs(Component parent) {
        JFileChooser chooser = new JFileChooser(getLastDirectory());
        chooser.setDialogTitle("Save JavaScript Inspector Session As");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
        int res = chooser.showSaveDialog(parent);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File sel = chooser.getSelectedFile();
            if (!sel.getName().toLowerCase().endsWith(".json")) {
                sel = new File(sel.getParentFile(), sel.getName() + ".json");
            }
            rememberDirectory(sel.getParent());
            this.activeSessionFile = sel;
            this.dirty.set(true);
            saveNow();
            updateStatusLabel();
            log("[JavaScript Inspector] Session saved as: " + sel.getAbsolutePath());
        }
    }

    public JPanel createSessionToolbarComponent(Component parent, Runnable onRefresh) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JButton newBtn = new JButton("New Session");
        newBtn.addActionListener(e -> {
            if (dirty.get() && activeSessionFile != null) {
                int res = JOptionPane.showConfirmDialog(parent, "Save current session before creating a new one?", "Unsaved Changes", JOptionPane.YES_NO_CANCEL_OPTION);
                if (res == JOptionPane.YES_OPTION) saveNow();
                else if (res == JOptionPane.CANCEL_OPTION) return;
            }
            JFileChooser dirChooser = new JFileChooser(getLastDirectory());
            dirChooser.setDialogTitle("Select Directory For New Session");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (dirChooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION && dirChooser.getSelectedFile() != null) {
                File dir = dirChooser.getSelectedFile();
                rememberDirectory(dir.getAbsolutePath());
                String name = JOptionPane.showInputDialog(parent, "Enter session filename:", "javascript_inspector_session.json");
                if (name != null && !name.isBlank()) {
                    if (!name.toLowerCase().endsWith(".json")) name += ".json";
                    createNewSessionFile(new File(dir, name.trim()));
                    if (onRefresh != null) SwingUtilities.invokeLater(onRefresh);
                }
            }
        });

        JButton openBtn = new JButton("Open Session");
        openBtn.addActionListener(e -> {
            if (dirty.get() && activeSessionFile != null) {
                int res = JOptionPane.showConfirmDialog(parent, "Save current session before opening another?", "Unsaved Changes", JOptionPane.YES_NO_CANCEL_OPTION);
                if (res == JOptionPane.YES_OPTION) saveNow();
                else if (res == JOptionPane.CANCEL_OPTION) return;
            }
            JFileChooser chooser = new JFileChooser(getLastDirectory());
            chooser.setDialogTitle("Select JavaScript Inspector Session File to Open");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                File sel = chooser.getSelectedFile();
                rememberDirectory(sel.getParent());
                openSessionFile(sel);
                if (onRefresh != null) SwingUtilities.invokeLater(onRefresh);
            }
        });

        JButton offboardBtn = new JButton("Offboard Session");
        offboardBtn.addActionListener(e -> offboardSession(parent, onRefresh));

        JButton saveAsBtn = new JButton("Save As...");
        saveAsBtn.addActionListener(e -> saveAs(parent));

        JButton saveNowBtn = new JButton("Save Now");
        saveNowBtn.addActionListener(e -> {
            if (activeSessionFile == null) {
                saveAs(parent);
            } else {
                saveNow();
                JOptionPane.showMessageDialog(parent, "Session saved successfully.", "Session Saved", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        bar.add(sessionStatusLabel);
        bar.add(newBtn);
        bar.add(openBtn);
        bar.add(offboardBtn);
        bar.add(saveAsBtn);
        bar.add(saveNowBtn);
        return bar;
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

    private void updateStatusLabel() {
        SwingUtilities.invokeLater(() -> {
            if (activeSessionFile != null) {
                sessionStatusLabel.setText("Session: " + activeSessionFile.getName() + " (" + activeSessionFile.getParent() + ")");
                sessionStatusLabel.setToolTipText(activeSessionFile.getAbsolutePath());
            } else {
                sessionStatusLabel.setText("Session: [Temporary / In-Memory]");
                sessionStatusLabel.setToolTipText("Data is currently in-memory. Use 'Save As...' to bind to a file.");
            }
        });
    }

    public void shutdown() {
        if (activeSessionFile != null && dirty.get()) {
            saveNow();
        }
        autoSaveExecutor.shutdownNow();
    }

    public File getActiveSessionFile() { return activeSessionFile; }
    public boolean isDirty() { return dirty.get(); }

    private void log(String msg) {
        if (api != null && api.logging() != null) api.logging().logToOutput(msg);
    }

    private void logError(String msg) {
        if (api != null && api.logging() != null) api.logging().logToError(msg);
    }
}
