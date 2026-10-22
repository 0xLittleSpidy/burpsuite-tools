// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapFinding;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.runner.ScanExecutionRecord;
import com.littlespidy.sqlmapanalyzer.runner.ScanRequestSession;
import com.littlespidy.sqlmapanalyzer.runner.ScanTaskManager;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * Child tab panel for a single HTTP request, managing its execution runs, request editor,
 * configuration, and real-time logs.
 * Plain ASCII text only.
 */
public class RequestScanTabPanel extends JPanel {

    private final MontoyaApi api;
    private final ScanRequestSession session;
    private final ScanTaskManager taskManager;

    private final JComboBox<String> executionCombo;
    private final JButton btnNewRun;
    private final JButton btnDeleteRun;

    private final RequestConfigPanel configPanel;
    private final HttpRequestEditor requestEditor;
    private final JTextArea rawArea;
    private final LogConsolePanel logConsolePanel;

    private boolean updatingCombo = false;

    public RequestScanTabPanel(MontoyaApi api, ScanRequestSession session, ScanTaskManager taskManager) {
        this.api = api;
        this.session = session;
        this.taskManager = taskManager;

        setLayout(new BorderLayout(0, 4));
        setBorder(new EmptyBorder(4, 6, 6, 6));

        // Top: Execution History Selector Bar
        JPanel topBar = new JPanel(new BorderLayout(10, 0));
        topBar.setBorder(new EmptyBorder(2, 4, 4, 4));

        JPanel leftExec = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        leftExec.add(SwingUtils.createBoldLabel("Execution Run:"));

        executionCombo = new JComboBox<>();
        executionCombo.setPreferredSize(new Dimension(280, 24));
        executionCombo.addActionListener(e -> {
            if (!updatingCombo) {
                onExecutionChanged();
            }
        });
        leftExec.add(executionCombo);

        btnNewRun = SwingUtils.createStyledButton("+ New Execution Run");
        btnNewRun.setToolTipText("Duplicate settings and create a fresh execution run for this endpoint");
        btnNewRun.addActionListener(e -> onNewExecution());
        leftExec.add(btnNewRun);

        btnDeleteRun = SwingUtils.createStyledButton("Delete Run");
        btnDeleteRun.addActionListener(e -> onDeleteExecution());
        leftExec.add(btnDeleteRun);

        topBar.add(leftExec, BorderLayout.WEST);
        add(topBar, BorderLayout.NORTH);

        // Center split pane: Configuration (Left) + Request Editor (Right)
        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        centerSplit.setResizeWeight(0.48);

        configPanel = new RequestConfigPanel(this::startScan, this::stopScan, this::syncRequestEditorToSession, this::onSslToggled);
        centerSplit.setLeftComponent(configPanel);

        // Right component: Native Montoya Request Editor
        if (api != null && api.userInterface() != null) {
            requestEditor = api.userInterface().createHttpRequestEditor();
            if (session.getRawRequest() != null && session.getRawRequest().length > 0) {
                try {
                    HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(session.getRawRequest()));
                    burp.api.montoya.http.HttpService service = com.littlespidy.sqlmapanalyzer.util.OSUtils.createHttpServiceFromUrl(api, session.getUrl());
                    if (service != null) {
                        req = req.withService(service);
                    }
                    requestEditor.setRequest(req);
                } catch (Exception ignored) {}
            }
            rawArea = null;
            centerSplit.setRightComponent(requestEditor.uiComponent());
        } else {
            requestEditor = null;
            rawArea = new JTextArea(new String(session.getRawRequest(), java.nio.charset.StandardCharsets.UTF_8));
            rawArea.setEditable(true);
            centerSplit.setRightComponent(new JScrollPane(rawArea));
        }

        // Bottom pane: Log console
        logConsolePanel = new LogConsolePanel();

        // Main vertical split: (Center config/request) on top, (LogConsole) on bottom
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.58);
        mainSplit.setTopComponent(centerSplit);
        mainSplit.setBottomComponent(logConsolePanel);

        add(mainSplit, BorderLayout.CENTER);

        syncHeadersToConfig();
        refreshExecutionDropdown();
        loadCurrentExecution();
    }

    private void syncHeadersToConfig() {
        java.util.Map<String, String> headers = null;
        if (requestEditor != null) {
            try {
                HttpRequest req = requestEditor.getRequest();
                if (req != null && req.headers() != null && !req.headers().isEmpty()) {
                    headers = new java.util.LinkedHashMap<>();
                    for (var h : req.headers()) {
                        String name = h.name();
                        String val = h.value();
                        if (headers.containsKey(name)) {
                            if ("cookie".equalsIgnoreCase(name)) {
                                headers.put(name, headers.get(name) + "; " + val);
                            } else {
                                headers.put(name, headers.get(name) + ", " + val);
                            }
                        } else {
                            headers.put(name, val);
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        if (headers == null || headers.isEmpty()) {
            headers = com.littlespidy.sqlmapanalyzer.util.OSUtils.parseHeadersFromRawRequest(session.getRawRequest());
        }

        if (headers != null && !headers.isEmpty()) {
            configPanel.setRequestHeaders(headers);
        }
    }

    public ScanRequestSession getSession() {
        syncRequestEditorToSession();
        return session;
    }

    public synchronized void syncRequestEditorToSession() {
        byte[] raw = null;
        String method = null;
        String url = null;
        String body = null;

        if (requestEditor != null) {
            try {
                HttpRequest req = requestEditor.getRequest();
                if (req != null) {
                    if (req.toByteArray() != null) {
                        raw = req.toByteArray().getBytes();
                    }
                    method = req.method();
                    url = com.littlespidy.sqlmapanalyzer.util.OSUtils.resolveFullUrl(req, session.getUrl());
                    body = req.bodyToString();
                }
            } catch (Exception ignored) {}
        } else if (rawArea != null) {
            String text = rawArea.getText();
            if (text != null && !text.isEmpty()) {
                raw = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                String[] lines = text.split("\r?\n");
                if (lines.length > 0 && !lines[0].trim().isEmpty()) {
                    String[] parts = lines[0].trim().split("\\s+");
                    if (parts.length > 0) method = parts[0].toUpperCase();
                }
                int headerEnd = text.indexOf("\r\n\r\n");
                if (headerEnd != -1) {
                    body = text.substring(headerEnd + 4);
                } else {
                    headerEnd = text.indexOf("\n\n");
                    if (headerEnd != -1) {
                        body = text.substring(headerEnd + 2);
                    }
                }
                url = com.littlespidy.sqlmapanalyzer.util.OSUtils.resolveFullUrlFromRaw(raw, session.getUrl());
            }
        }

        if (raw != null && raw.length > 0) {
            session.updateRequest(method, url, raw);
            ScanExecutionRecord active = session.getActiveExecution();
            if (active != null && active.getOptions() != null) {
                SqlmapTaskOptions opts = active.getOptions();
                if (url != null && !url.isEmpty()) {
                    opts.setUrl(url);
                }
                if (method != null && !method.isEmpty()) {
                    opts.setMethod(method);
                }
                if (body != null) {
                    opts.setData(body.isEmpty() ? null : body);
                }
            }
            syncHeadersToConfig();

            // Update parent tab title if not custom-renamed
            SwingUtilities.invokeLater(() -> {
                JTabbedPane parentPane = (JTabbedPane) SwingUtilities.getAncestorOfClass(JTabbedPane.class, this);
                if (parentPane != null) {
                    int idx = parentPane.indexOfComponent(this);
                    if (idx != -1) {
                        Component headerComp = parentPane.getTabComponentAt(idx);
                        if (headerComp instanceof CloseableTabHeader_littlespidy) {
                            CloseableTabHeader_littlespidy header = (CloseableTabHeader_littlespidy) headerComp;
                            if (session.getCustomTabTitle() == null || session.getCustomTabTitle().isEmpty()) {
                                header.setTitle(session.getTabTitle());
                                parentPane.setTitleAt(idx, session.getTabTitle());
                            }
                        }
                    }
                }
            });
        }
    }

    public JTextArea getRawAreaForTest() {
        return rawArea;
    }

    public RequestConfigPanel getConfigPanelForTest() {
        return configPanel;
    }

    private void onSslToggled(boolean forceSsl) {
        String sessionUrl = session.getUrl();
        if (sessionUrl != null && !sessionUrl.isBlank()) {
            if (forceSsl && sessionUrl.startsWith("http://")) {
                session.setUrl("https://" + sessionUrl.substring(7));
            } else if (!forceSsl && sessionUrl.startsWith("https://")) {
                session.setUrl("http://" + sessionUrl.substring(8));
            }
        }
        ScanExecutionRecord active = session.getActiveExecution();
        if (active != null && active.getOptions() != null) {
            active.getOptions().setForceSsl(forceSsl);
            String optUrl = active.getOptions().getUrl();
            if (optUrl != null && !optUrl.isBlank()) {
                if (forceSsl && optUrl.startsWith("http://")) {
                    active.getOptions().setUrl("https://" + optUrl.substring(7));
                } else if (!forceSsl && optUrl.startsWith("https://")) {
                    active.getOptions().setUrl("http://" + optUrl.substring(8));
                }
            }
        }
    }

    private void refreshExecutionDropdown() {
        updatingCombo = true;
        try {
            executionCombo.removeAllItems();
            List<ScanExecutionRecord> runs = session.getExecutions();
            for (ScanExecutionRecord r : runs) {
                executionCombo.addItem(r.getDisplayName());
            }
            if (session.getActiveExecutionIndex() < executionCombo.getItemCount()) {
                executionCombo.setSelectedIndex(session.getActiveExecutionIndex());
            }
        } finally {
            updatingCombo = false;
        }
    }

    private void onExecutionChanged() {
        int idx = executionCombo.getSelectedIndex();
        if (idx >= 0 && idx < session.getExecutions().size()) {
            session.setActiveExecutionIndex(idx);
            loadCurrentExecution();
        }
    }

    private void loadCurrentExecution() {
        ScanExecutionRecord active = session.getActiveExecution();
        if (active == null) return;

        configPanel.loadOptions(active.getOptions());
        logConsolePanel.updateFromRecord(active);

        boolean isRunning = taskManager != null && taskManager.isScanning(active);
        configPanel.setScanningState(isRunning);
    }

    private void onNewExecution() {
        syncRequestEditorToSession();
        ScanExecutionRecord newRun = session.createNewExecution();
        refreshExecutionDropdown();
        loadCurrentExecution();
    }

    private void onDeleteExecution() {
        int idx = session.getActiveExecutionIndex();
        boolean deleted = session.deleteExecution(idx);
        if (deleted) {
            refreshExecutionDropdown();
            loadCurrentExecution();
        } else {
            JOptionPane.showMessageDialog(this, "Cannot delete the only execution run for this endpoint.",
                    "Delete Run", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void startScan() {
        syncRequestEditorToSession();
        ScanExecutionRecord active = session.getActiveExecution();
        if (active == null) return;

        String currentStatus = active.getStatus();
        if ("COMPLETED".equalsIgnoreCase(currentStatus) || "VULNERABLE".equalsIgnoreCase(currentStatus) || "ERROR".equalsIgnoreCase(currentStatus)) {
            active = session.createNewExecution();
            refreshExecutionDropdown();
            loadCurrentExecution();
        } else if ("CANCELLED".equalsIgnoreCase(currentStatus) || active.isCancelled()) {
            active.setCancelled(false);
            active.setStatus("READY");
            active.addLog(new SqlmapLogEntry("INFO", "", "Restarting cancelled scan execution run..."));
            logConsolePanel.updateFromRecord(active);
            refreshExecutionDropdown();
        }

        syncHeadersToConfig();
        active.setOptions(configPanel.applyUiToOptions());
        configPanel.setScanningState(true);
        logConsolePanel.setStatusBadge("RUNNING", false);
        logConsolePanel.updateFromRecord(active);

        if (taskManager != null) {
            taskManager.startScan(active, new ScanTaskManager.ScanUpdateListener() {
                @Override
                public void onLogsUpdated(ScanExecutionRecord record, List<SqlmapLogEntry> newLogs) {
                    SwingUtils.runOnEdt(() -> {
                        if (record == session.getActiveExecution()) {
                            logConsolePanel.appendLogs(newLogs);
                        }
                    });
                }

                @Override
                public void onStatusChanged(ScanExecutionRecord record, String status) {
                    SwingUtils.runOnEdt(() -> {
                        if (record == session.getActiveExecution()) {
                            logConsolePanel.setStatusBadge(status, record.isVulnerable());
                        }
                        refreshExecutionDropdown();
                    });
                }

                @Override
                public void onFindingsUpdated(ScanExecutionRecord record, List<SqlmapFinding> findings) {
                    SwingUtils.runOnEdt(() -> {
                        if (record == session.getActiveExecution()) {
                            logConsolePanel.updateFindings(findings);
                        }
                        refreshExecutionDropdown();
                    });
                }

                @Override
                public void onScanComplete(ScanExecutionRecord record) {
                    SwingUtils.runOnEdt(() -> {
                        if (record == session.getActiveExecution()) {
                            configPanel.setScanningState(false);
                            logConsolePanel.setStatusBadge(record.getStatus(), record.isVulnerable());
                        }
                        refreshExecutionDropdown();
                    });
                }

                @Override
                public void onScanError(ScanExecutionRecord record, String errorMessage) {
                    SwingUtils.runOnEdt(() -> {
                        if (record == session.getActiveExecution()) {
                            configPanel.setScanningState(false);
                            logConsolePanel.setStatusBadge(record.getStatus(), record.isVulnerable());
                            JOptionPane.showMessageDialog(RequestScanTabPanel.this, errorMessage, "Scan Error", JOptionPane.ERROR_MESSAGE);
                        }
                        refreshExecutionDropdown();
                    });
                }
            });
        }
    }

    private void stopScan() {
        ScanExecutionRecord active = session.getActiveExecution();
        if (active == null) return;

        if (taskManager != null) {
            taskManager.cancelScan(active);
        }
        configPanel.setScanningState(false);
        logConsolePanel.setStatusBadge("CANCELLED", false);
        logConsolePanel.updateFromRecord(active);
        refreshExecutionDropdown();
    }

    public void cleanup() {
        ScanExecutionRecord active = session.getActiveExecution();
        if (active != null && taskManager != null && taskManager.isScanning(active)) {
            taskManager.cancelScan(active);
        }
    }
}
