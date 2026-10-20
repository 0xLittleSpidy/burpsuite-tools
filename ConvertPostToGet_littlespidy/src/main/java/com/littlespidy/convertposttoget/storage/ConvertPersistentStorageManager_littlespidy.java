// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.convertposttoget.model.*;
import com.littlespidy.convertposttoget.storage.ConvertSessionDTO_littlespidy.*;
import com.littlespidy.convertposttoget.ui.ConvertPostToGetTab;
import com.littlespidy.convertposttoget.ui.ConvertSessionPanel;

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
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for Convert POST to GET.
 */
public class ConvertPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ConvertPostToGet-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private ScheduledFuture<?> scheduledSaveTask = null;
    private ConvertPostToGetTab boundTab = null;

    private final JLabel sessionStatusLabel;

    public ConvertPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    }

    public void bindTab(ConvertPostToGetTab tab) {
        this.boundTab = tab;
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

            if (boundTab != null) {
                boundTab.clearAll();

                // 1. Restore POST Sweep Candidates
                List<PostCandidate> sweepCandidates = new ArrayList<>();
                if (root.sweepCandidates != null) {
                    for (PostCandidateDTO dto : root.sweepCandidates) {
                        sweepCandidates.add(restoreCandidate(dto));
                    }
                }
                boundTab.getTrafficSweepPanel().setCandidates(sweepCandidates);

                // 2. Restore Active Attack Sessions
                if (root.sessions != null) {
                    for (ConvertSessionDTO sDto : root.sessions) {
                        List<PostCandidate> targets = new ArrayList<>();
                        if (sDto.targets != null) {
                            for (PostCandidateDTO tDto : sDto.targets) {
                                targets.add(restoreCandidate(tDto));
                            }
                        }

                        List<ConfiguredHeader> headers = new ArrayList<>();
                        if (sDto.customHeaders != null) {
                            for (ConfiguredHeaderDTO hDto : sDto.customHeaders) {
                                headers.add(new ConfiguredHeader(hDto.name, hDto.value));
                            }
                        }

                        List<ConversionResult> results = new ArrayList<>();
                        if (sDto.results != null) {
                            for (ConversionResultDTO rDto : sDto.results) {
                                results.add(restoreConversionResult(rDto));
                            }
                        }

                        boundTab.restoreSessionTab(sDto.title, targets, headers, results);
                    }
                }
            }

            this.activeSessionFile = file;
            this.dirty.set(false);
            updateStatusLabel();
            log("[Convert POST to GET] Session opened successfully from: " + file.getAbsolutePath());
        } catch (Exception ex) {
            logError("[Convert POST to GET] Failed to open session from " + file.getAbsolutePath() + ": " + ex.getMessage());
            JOptionPane.showMessageDialog(null, "Failed to load session file:\n" + ex.getMessage(), "Session Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public synchronized void createNewSessionFile(File file) {
        if (file == null) return;
        if (boundTab != null) {
            boundTab.clearAll();
        }
        this.activeSessionFile = file;
        this.dirty.set(true);
        saveNow();
        updateStatusLabel();
        log("[Convert POST to GET] Created new session bound to: " + file.getAbsolutePath());
    }

    public synchronized void startTemporarySession() {
        if (boundTab != null) {
            boundTab.clearAll();
        }
        this.activeSessionFile = null;
        this.dirty.set(false);
        updateStatusLabel();
        log("[Convert POST to GET] Started temporary in-memory session.");
    }

    public synchronized void offboardSession(Component parent, Runnable onRefresh) {
        if (activeSessionFile == null) {
            if (boundTab != null) {
                boundTab.clearAll();
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

        if (boundTab != null) {
            boundTab.clearAll();
        }

        updateStatusLabel();
        if (onRefresh != null) {
            SwingUtilities.invokeLater(onRefresh);
        }
        log("[Convert POST to GET] Offboarded session " + (previousFile != null ? previousFile.getName() : "") + ". Restored fresh clean state.");
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

            if (boundTab != null) {
                // 1. Sweep candidates
                List<PostCandidate> sweepCandidates = boundTab.getTrafficSweepPanel().getCandidates();
                if (sweepCandidates != null) {
                    for (PostCandidate c : sweepCandidates) {
                        root.sweepCandidates.add(toCandidateDTO(c));
                    }
                }

                // 2. Active attack sessions
                List<ConvertSessionPanel> sessions = boundTab.getActiveSessions();
                if (sessions != null) {
                    for (ConvertSessionPanel s : sessions) {
                        ConvertSessionDTO sDto = new ConvertSessionDTO();
                        sDto.title = s.getSessionTitle();

                        for (PostCandidate t : s.getTargetCandidates()) {
                            sDto.targets.add(toCandidateDTO(t));
                        }

                        for (ConfiguredHeader h : s.getSessionHeaders()) {
                            ConfiguredHeaderDTO hDto = new ConfiguredHeaderDTO();
                            hDto.name = h.name();
                            hDto.value = h.value();
                            sDto.customHeaders.add(hDto);
                        }

                        for (ConversionResult r : s.getResults()) {
                            sDto.results.add(toConversionResultDTO(r));
                        }

                        root.sessions.add(sDto);
                    }
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
            logError("[Convert POST to GET] Error saving session to " + activeSessionFile.getAbsolutePath() + ": " + ex.getMessage());
        }
    }

    public synchronized void saveAs(Component parent) {
        JFileChooser chooser = new JFileChooser(getLastDirectory());
        chooser.setDialogTitle("Save Convert POST to GET Session As");
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
            log("[Convert POST to GET] Session saved as: " + sel.getAbsolutePath());
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
                String name = JOptionPane.showInputDialog(parent, "Enter session filename:", "convert_post_to_get_session.json");
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
            chooser.setDialogTitle("Select Convert POST to GET Session File to Open");
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

    private PostCandidateDTO toCandidateDTO(PostCandidate c) {
        PostCandidateDTO dto = new PostCandidateDTO();
        dto.id = c.id();
        dto.method = c.method();
        dto.url = c.url();
        dto.host = c.host();
        dto.path = c.path();
        dto.statusCode = c.statusCode();
        dto.contentLength = c.contentLength();
        dto.contentType = c.contentType();
        dto.parameterCount = c.parameterCount();
        dto.parameterNames = new ArrayList<>(c.parameterNames());
        dto.parameterTypes = new HashSet<>(c.parameterTypes());
        dto.isAuthenticated = c.isAuthenticated();
        dto.authIndicator = c.authIndicator();
        dto.dedupeKey = c.dedupeKey();
        dto.timestamp = c.time() != null ? c.time().toString() : "";

        if (c.request() != null) {
            dto.hasRequest = true;
            dto.requestBase64 = Base64.getEncoder().encodeToString(c.request().toByteArray().getBytes());
            if (c.request().httpService() != null) {
                dto.requestHost = c.request().httpService().host();
                dto.requestPort = c.request().httpService().port();
                dto.requestSecure = c.request().httpService().secure();
            }
        }

        if (c.response() != null) {
            dto.hasResponse = true;
            dto.responseBase64 = Base64.getEncoder().encodeToString(c.response().toByteArray().getBytes());
        }

        return dto;
    }

    private PostCandidate restoreCandidate(PostCandidateDTO dto) {
        HttpRequest req = null;
        if (dto.hasRequest && dto.requestBase64 != null && !dto.requestBase64.isEmpty()) {
            try {
                byte[] b = Base64.getDecoder().decode(dto.requestBase64);
                HttpService svc = (dto.requestHost != null && !dto.requestHost.isBlank())
                        ? HttpService.httpService(dto.requestHost, dto.requestPort > 0 ? dto.requestPort : (dto.requestSecure ? 443 : 80), dto.requestSecure)
                        : null;
                ByteArray ba = ByteArray.byteArray(b);
                req = (svc != null) ? HttpRequest.httpRequest(svc, ba) : HttpRequest.httpRequest(ba);
            } catch (Exception ignored) {}
        }

        HttpResponse resp = null;
        if (dto.hasResponse && dto.responseBase64 != null && !dto.responseBase64.isEmpty()) {
            try {
                byte[] b = Base64.getDecoder().decode(dto.responseBase64);
                resp = HttpResponse.httpResponse(ByteArray.byteArray(b));
            } catch (Exception ignored) {}
        }

        ZonedDateTime ts = null;
        if (dto.timestamp != null && !dto.timestamp.isBlank()) {
            try {
                ts = ZonedDateTime.parse(dto.timestamp);
            } catch (Exception ignored) {}
        }
        if (ts == null) ts = ZonedDateTime.now();

        return new PostCandidate(
                dto.id,
                dto.method,
                dto.url,
                dto.host,
                dto.path,
                dto.statusCode,
                dto.contentLength,
                dto.contentType,
                dto.parameterCount,
                dto.parameterNames != null ? dto.parameterNames : List.of(),
                dto.parameterTypes != null ? dto.parameterTypes : java.util.Collections.emptySet(),
                dto.isAuthenticated,
                dto.authIndicator,
                dto.dedupeKey,
                req,
                resp,
                ts
        );
    }

    private ConversionResultDTO toConversionResultDTO(ConversionResult r) {
        ConversionResultDTO dto = new ConversionResultDTO();
        dto.id = r.id();
        dto.method = r.method();
        dto.url = r.url();
        dto.host = r.host();
        dto.path = r.path();
        dto.baseStatus = r.baseStatus();
        dto.baseLength = r.baseLength();
        dto.getStatus = r.getStatus();
        dto.getLength = r.getLength();
        dto.getContentType = r.getContentType();
        dto.signal = r.signal();
        dto.severity = r.severity();
        dto.evidence = r.evidence();
        dto.timestamp = r.timestamp() != null ? r.timestamp().toString() : "";

        if (r.originalPostRequest() != null) {
            dto.hasOriginalRequest = true;
            dto.originalRequestBase64 = Base64.getEncoder().encodeToString(r.originalPostRequest().toByteArray().getBytes());
            if (r.originalPostRequest().httpService() != null) {
                dto.originalRequestHost = r.originalPostRequest().httpService().host();
                dto.originalRequestPort = r.originalPostRequest().httpService().port();
                dto.originalRequestSecure = r.originalPostRequest().httpService().secure();
            }
        }

        if (r.originalPostResponse() != null) {
            dto.hasOriginalResponse = true;
            dto.originalResponseBase64 = Base64.getEncoder().encodeToString(r.originalPostResponse().toByteArray().getBytes());
        }

        if (r.convertedGetRequest() != null) {
            dto.hasConvertedRequest = true;
            dto.convertedRequestBase64 = Base64.getEncoder().encodeToString(r.convertedGetRequest().toByteArray().getBytes());
            if (r.convertedGetRequest().httpService() != null) {
                dto.convertedRequestHost = r.convertedGetRequest().httpService().host();
                dto.convertedRequestPort = r.convertedGetRequest().httpService().port();
                dto.convertedRequestSecure = r.convertedGetRequest().httpService().secure();
            }
        }

        if (r.convertedGetResponse() != null) {
            dto.hasConvertedResponse = true;
            dto.convertedResponseBase64 = Base64.getEncoder().encodeToString(r.convertedGetResponse().toByteArray().getBytes());
        }

        return dto;
    }

    private ConversionResult restoreConversionResult(ConversionResultDTO dto) {
        HttpRequest origReq = null;
        if (dto.hasOriginalRequest && dto.originalRequestBase64 != null && !dto.originalRequestBase64.isEmpty()) {
            try {
                byte[] b = Base64.getDecoder().decode(dto.originalRequestBase64);
                HttpService svc = (dto.originalRequestHost != null && !dto.originalRequestHost.isBlank())
                        ? HttpService.httpService(dto.originalRequestHost, dto.originalRequestPort > 0 ? dto.originalRequestPort : (dto.originalRequestSecure ? 443 : 80), dto.originalRequestSecure)
                        : null;
                ByteArray ba = ByteArray.byteArray(b);
                origReq = (svc != null) ? HttpRequest.httpRequest(svc, ba) : HttpRequest.httpRequest(ba);
            } catch (Exception ignored) {}
        }

        HttpResponse origResp = null;
        if (dto.hasOriginalResponse && dto.originalResponseBase64 != null && !dto.originalResponseBase64.isEmpty()) {
            try {
                byte[] b = Base64.getDecoder().decode(dto.originalResponseBase64);
                origResp = HttpResponse.httpResponse(ByteArray.byteArray(b));
            } catch (Exception ignored) {}
        }

        HttpRequest convReq = null;
        if (dto.hasConvertedRequest && dto.convertedRequestBase64 != null && !dto.convertedRequestBase64.isEmpty()) {
            try {
                byte[] b = Base64.getDecoder().decode(dto.convertedRequestBase64);
                HttpService svc = (dto.convertedRequestHost != null && !dto.convertedRequestHost.isBlank())
                        ? HttpService.httpService(dto.convertedRequestHost, dto.convertedRequestPort > 0 ? dto.convertedRequestPort : (dto.convertedRequestSecure ? 443 : 80), dto.convertedRequestSecure)
                        : null;
                ByteArray ba = ByteArray.byteArray(b);
                convReq = (svc != null) ? HttpRequest.httpRequest(svc, ba) : HttpRequest.httpRequest(ba);
            } catch (Exception ignored) {}
        }

        HttpResponse convResp = null;
        if (dto.hasConvertedResponse && dto.convertedResponseBase64 != null && !dto.convertedResponseBase64.isEmpty()) {
            try {
                byte[] b = Base64.getDecoder().decode(dto.convertedResponseBase64);
                convResp = HttpResponse.httpResponse(ByteArray.byteArray(b));
            } catch (Exception ignored) {}
        }

        HttpRequestResponse rr = null;
        if (convReq != null) {
            rr = (convResp != null) ? HttpRequestResponse.httpRequestResponse(convReq, convResp) : HttpRequestResponse.httpRequestResponse(convReq, HttpResponse.httpResponse(ByteArray.byteArray(new byte[0])));
        }

        ZonedDateTime ts = null;
        if (dto.timestamp != null && !dto.timestamp.isBlank()) {
            try {
                ts = ZonedDateTime.parse(dto.timestamp);
            } catch (Exception ignored) {}
        }
        if (ts == null) ts = ZonedDateTime.now();

        return new ConversionResult(
                dto.id,
                dto.method,
                dto.url,
                dto.host,
                dto.path,
                dto.baseStatus,
                dto.baseLength,
                dto.getStatus,
                dto.getLength,
                dto.getContentType,
                dto.signal,
                dto.severity,
                dto.evidence,
                origReq,
                origResp,
                convReq,
                convResp,
                rr,
                ts
        );
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
