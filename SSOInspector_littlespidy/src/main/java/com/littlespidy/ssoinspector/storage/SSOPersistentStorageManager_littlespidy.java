// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.ssoinspector.model.*;
import com.littlespidy.ssoinspector.storage.SSOSessionDTO_littlespidy.OAuthEntryDTO;
import com.littlespidy.ssoinspector.storage.SSOSessionDTO_littlespidy.OAuthParamDTO;
import com.littlespidy.ssoinspector.storage.SSOSessionDTO_littlespidy.SSOAuditIssueDTO;
import com.littlespidy.ssoinspector.storage.SSOSessionDTO_littlespidy.SessionRootDTO;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages persistent storage, state recovery, and clean offboarding for SSO Inspector.
 */
public class SSOPersistentStorageManager_littlespidy {

    private final MontoyaApi api;
    private final Gson gson;
    private volatile File activeSessionFile = null;

    private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "SSOInspector-SessionAutoSave");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private ScheduledFuture<?> scheduledSaveTask = null;
    private OAuthDataStore boundDataStore = null;

    private final JLabel sessionStatusLabel;

    public SSOPersistentStorageManager_littlespidy(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        this.sessionStatusLabel = new JLabel("Session: [Fresh / Unbound]");
        this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    }

    public void bindDataStore(OAuthDataStore dataStore) {
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
                int maxId = 0;

                if (root.entries != null) {
                    for (OAuthEntryDTO dto : root.entries) {
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

                        HttpRequestResponse rr = null;
                        if (req != null) {
                            rr = (resp != null) ? HttpRequestResponse.httpRequestResponse(req, resp) : HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse(ByteArray.byteArray(new byte[0])));
                        }

                        OAuthRequestEntry entry = new OAuthRequestEntry(dto.id, dto.timestamp, rr);

                        // Flow Type
                        OAuthFlowType flowType = OAuthFlowType.UNKNOWN_OR_CUSTOM;
                        if (dto.flowType != null) {
                            for (OAuthFlowType candidate : OAuthFlowType.values()) {
                                if (candidate.name().equalsIgnoreCase(dto.flowType) || candidate.getDisplayName().equalsIgnoreCase(dto.flowType)) {
                                    flowType = candidate;
                                    break;
                                }
                            }
                        }
                        entry.setFlowType(flowType);

                        // Parameters
                        List<OAuthParam> params = new ArrayList<>();
                        if (dto.parameters != null) {
                            for (OAuthParamDTO pDto : dto.parameters) {
                                OAuthParam.ParamLocation loc = OAuthParam.ParamLocation.UNKNOWN;
                                if (pDto.location != null) {
                                    try {
                                        loc = OAuthParam.ParamLocation.valueOf(pDto.location);
                                    } catch (Exception ignored) {
                                        for (OAuthParam.ParamLocation candidate : OAuthParam.ParamLocation.values()) {
                                            if (candidate.getLabel().equalsIgnoreCase(pDto.location)) {
                                                loc = candidate;
                                                break;
                                            }
                                        }
                                    }
                                }
                                params.add(new OAuthParam(pDto.name, pDto.rawValue, pDto.decodedValue, loc, pDto.description, pDto.standard, pDto.sensitive));
                            }
                        }
                        entry.setParameters(params);

                        // Issues
                        List<SSOAuditIssue> issues = new ArrayList<>();
                        if (dto.issues != null) {
                            for (SSOAuditIssueDTO iDto : dto.issues) {
                                IssueSeverity sev = IssueSeverity.fromString(iDto.severity);
                                IssueConfidence conf = IssueConfidence.fromString(iDto.confidence);

                                HttpRequestResponse issueMsg = rr;
                                if (iDto.hasIssueMessage && iDto.issueRequestBase64 != null && !iDto.issueRequestBase64.isEmpty()) {
                                    try {
                                        byte[] issueReqBytes = Base64.getDecoder().decode(iDto.issueRequestBase64);
                                        HttpService issueSvc = (iDto.issueHost != null && !iDto.issueHost.isBlank())
                                                ? HttpService.httpService(iDto.issueHost, iDto.issuePort > 0 ? iDto.issuePort : (iDto.issueSecure ? 443 : 80), iDto.issueSecure)
                                                : null;
                                        ByteArray ba = ByteArray.byteArray(issueReqBytes);
                                        HttpRequest issueReq = (issueSvc != null) ? HttpRequest.httpRequest(issueSvc, ba) : HttpRequest.httpRequest(ba);

                                        HttpResponse issueResp = null;
                                        if (iDto.issueResponseBase64 != null && !iDto.issueResponseBase64.isEmpty()) {
                                            byte[] issueRespBytes = Base64.getDecoder().decode(iDto.issueResponseBase64);
                                            issueResp = HttpResponse.httpResponse(ByteArray.byteArray(issueRespBytes));
                                        }
                                        issueMsg = (issueResp != null) ? HttpRequestResponse.httpRequestResponse(issueReq, issueResp) : HttpRequestResponse.httpRequestResponse(issueReq, HttpResponse.httpResponse(ByteArray.byteArray(new byte[0])));
                                    } catch (Exception ignored) {}
                                }

                                issues.add(new SSOAuditIssue(iDto.title, sev, conf, iDto.description, iDto.remediation, iDto.references, issueMsg, iDto.activeProbe));
                            }
                        }
                        entry.setIssues(issues);

                        boundDataStore.addEntry(entry);
                        if (dto.id > maxId) {
                            maxId = dto.id;
                        }
                    }
                }

                boundDataStore.setNextId(maxId + 1);
            }

            this.activeSessionFile = file;
            this.dirty.set(false);
            updateStatusLabel();
            log("[SSO Inspector] Session opened successfully from: " + file.getAbsolutePath());
        } catch (Exception ex) {
            logError("[SSO Inspector] Failed to open session from " + file.getAbsolutePath() + ": " + ex.getMessage());
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
        log("[SSO Inspector] Created new session bound to: " + file.getAbsolutePath());
    }

    public synchronized void startTemporarySession() {
        if (boundDataStore != null) {
            boundDataStore.clear();
        }
        this.activeSessionFile = null;
        this.dirty.set(false);
        updateStatusLabel();
        log("[SSO Inspector] Started temporary in-memory session.");
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
        log("[SSO Inspector] Offboarded session " + (previousFile != null ? previousFile.getName() : "") + ". Restored fresh clean state.");
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
                for (OAuthRequestEntry e : boundDataStore.getAllEntries()) {
                    OAuthEntryDTO dto = new OAuthEntryDTO();
                    dto.id = e.getId();
                    dto.timestamp = e.getTimestamp();
                    dto.method = e.getMethod();
                    dto.host = e.getHost();
                    dto.path = e.getPath();
                    dto.url = e.getUrl();
                    dto.statusCode = e.getStatusCode();
                    dto.flowType = e.getFlowType() != null ? e.getFlowType().name() : OAuthFlowType.UNKNOWN_OR_CUSTOM.name();

                    if (e.getOriginalRequestResponse() != null) {
                        HttpRequest req = e.getOriginalRequestResponse().request();
                        if (req != null) {
                            dto.hasRequest = true;
                            dto.requestBase64 = Base64.getEncoder().encodeToString(req.toByteArray().getBytes());
                            if (req.httpService() != null) {
                                dto.requestHost = req.httpService().host();
                                dto.requestPort = req.httpService().port();
                                dto.requestSecure = req.httpService().secure();
                            }
                        }

                        HttpResponse resp = e.getOriginalRequestResponse().response();
                        if (resp != null) {
                            dto.hasResponse = true;
                            dto.responseBase64 = Base64.getEncoder().encodeToString(resp.toByteArray().getBytes());
                        }
                    }

                    // Parameters
                    for (OAuthParam p : e.getParameters()) {
                        OAuthParamDTO pDto = new OAuthParamDTO();
                        pDto.name = p.getName();
                        pDto.rawValue = p.getRawValue();
                        pDto.decodedValue = p.getDecodedValue();
                        pDto.location = p.getLocation() != null ? p.getLocation().name() : OAuthParam.ParamLocation.UNKNOWN.name();
                        pDto.description = p.getDescription();
                        pDto.standard = p.isStandard();
                        pDto.sensitive = p.isSensitive();
                        dto.parameters.add(pDto);
                    }

                    // Issues
                    for (SSOAuditIssue issue : e.getIssues()) {
                        SSOAuditIssueDTO iDto = new SSOAuditIssueDTO();
                        iDto.title = issue.getTitle();
                        iDto.severity = issue.getSeverity() != null ? issue.getSeverity().getLabel() : IssueSeverity.INFORMATION.getLabel();
                        iDto.confidence = issue.getConfidence() != null ? issue.getConfidence().getLabel() : IssueConfidence.TENTATIVE.getLabel();
                        iDto.description = issue.getDescription();
                        iDto.remediation = issue.getRemediation();
                        iDto.references = issue.getReferences();
                        iDto.activeProbe = issue.isActiveProbe();

                        if (issue.getHttpMessage() != null && issue.getHttpMessage() != e.getOriginalRequestResponse()) {
                            HttpRequest iReq = issue.getHttpMessage().request();
                            if (iReq != null) {
                                iDto.hasIssueMessage = true;
                                iDto.issueRequestBase64 = Base64.getEncoder().encodeToString(iReq.toByteArray().getBytes());
                                if (iReq.httpService() != null) {
                                    iDto.issueHost = iReq.httpService().host();
                                    iDto.issuePort = iReq.httpService().port();
                                    iDto.issueSecure = iReq.httpService().secure();
                                }
                            }
                            HttpResponse iResp = issue.getHttpMessage().response();
                            if (iResp != null) {
                                iDto.issueResponseBase64 = Base64.getEncoder().encodeToString(iResp.toByteArray().getBytes());
                            }
                        }
                        dto.issues.add(iDto);
                    }

                    root.entries.add(dto);
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
            logError("[SSO Inspector] Error saving session to " + activeSessionFile.getAbsolutePath() + ": " + ex.getMessage());
        }
    }

    public synchronized void saveAs(Component parent) {
        JFileChooser chooser = new JFileChooser(getLastDirectory());
        chooser.setDialogTitle("Save SSO Inspector Session As");
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
            log("[SSO Inspector] Session saved as: " + sel.getAbsolutePath());
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
                String name = JOptionPane.showInputDialog(parent, "Enter session filename:", "sso_inspector_session.json");
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
            chooser.setDialogTitle("Select SSO Inspector Session File to Open");
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
