// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.graphqlcop.engine.AuditEngine_littlespidy;
import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.HttpLogEntry_littlespidy;
import com.littlespidy.graphqlcop.model.SessionData_littlespidy;
import com.littlespidy.graphqlcop.voyager.LocalVoyagerServer_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public class GraphQLSessionPanel_littlespidy extends JPanel {
    private final MontoyaApi api;
    private final LocalVoyagerServer_littlespidy voyagerServer;
    private final AuditEngine_littlespidy auditEngine;
    private final Consumer<Void> saveTrigger;

    private final String sessionId;
    private String tabTitle;
    private final JTextField targetUrlField;
    private final JButton sessionHeadersBtn;
    private final JButton runAllBtn;
    private final JButton stopBtn;
    private final JLabel statusLabel;

    private String customHeaders = "";

    private final AuditingSubTab_littlespidy auditingTab;
    private final HttpHistorySubTab_littlespidy historyTab;
    private final QueryVoyagerSubTab_littlespidy voyagerTab;
    private final SchemaIntelligenceSubTab_littlespidy intelTab;

    public GraphQLSessionPanel_littlespidy(MontoyaApi api, LocalVoyagerServer_littlespidy voyagerServer,
                                          String sessionId, String tabTitle, String initialUrl,
                                          Consumer<Void> saveTrigger) {
        super(new BorderLayout());
        this.api = api;
        this.voyagerServer = voyagerServer;
        this.auditEngine = new AuditEngine_littlespidy(api);
        this.sessionId = sessionId != null ? sessionId : UUID.randomUUID().toString();
        this.tabTitle = tabTitle;
        this.saveTrigger = saveTrigger;

        // Top Controls Panel
        JPanel topPanel = new JPanel(new BorderLayout(6, 6));
        topPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel inputsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        inputsRow.add(new JLabel("Target GraphQL URL:"));
        targetUrlField = new JTextField(initialUrl != null ? initialUrl : "https://", 32);
        inputsRow.add(targetUrlField);

        sessionHeadersBtn = new JButton("[Session Headers (0 set)]");
        sessionHeadersBtn.addActionListener(e -> openHeadersDialog());
        inputsRow.add(sessionHeadersBtn);

        runAllBtn = new JButton("Run All Probes");
        runAllBtn.setFont(runAllBtn.getFont().deriveFont(Font.BOLD));
        runAllBtn.addActionListener(e -> runAllProbes());
        inputsRow.add(runAllBtn);

        stopBtn = new JButton("Stop Probes");
        stopBtn.setFont(stopBtn.getFont().deriveFont(Font.BOLD));
        stopBtn.setForeground(new Color(180, 40, 40));
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopProbes());
        inputsRow.add(stopBtn);

        statusLabel = new JLabel("Status: Idle");
        inputsRow.add(statusLabel);

        topPanel.add(inputsRow, BorderLayout.CENTER);
        add(topPanel, BorderLayout.NORTH);

        // Sub Tabs
        JTabbedPane subTabs = new JTabbedPane();

        auditingTab = new AuditingSubTab_littlespidy(api, this::runSingleProbe, this::stopProbes);
        historyTab = new HttpHistorySubTab_littlespidy(api);
        voyagerTab = new QueryVoyagerSubTab_littlespidy(api, voyagerServer, this::getTargetUrl, this::getCustomHeaders);
        intelTab = new SchemaIntelligenceSubTab_littlespidy(voyagerTab::getCurrentIntrospectionJson);

        subTabs.addTab("Auditing & Probes", auditingTab);
        subTabs.addTab("HTTP History", historyTab);
        subTabs.addTab("Query & Schema Voyager", voyagerTab);
        subTabs.addTab("Schema Intelligence (InQL)", intelTab);

        add(subTabs, BorderLayout.CENTER);
    }

    private void openHeadersDialog() {
        Window window = SwingUtilities.getWindowAncestor(this);
        AuthHeadersDialog_littlespidy dialog = new AuthHeadersDialog_littlespidy(window, customHeaders);
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            customHeaders = dialog.getHeadersText();
            updateHeadersButtonLabel();
            triggerSave();
        }
    }

    private void updateHeadersButtonLabel() {
        int count = 0;
        if (!customHeaders.isEmpty()) {
            for (String line : customHeaders.split("\\r?\\n")) {
                if (line.contains(":")) count++;
            }
        }
        sessionHeadersBtn.setText("[Session Headers (" + count + " set)]");
    }

    public void runAllProbes() {
        String target = getTargetUrl();
        if (target.isEmpty() || !target.startsWith("http")) {
            JOptionPane.showMessageDialog(this, "Please enter a valid HTTP/HTTPS GraphQL target URL.", "Target Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        runAllBtn.setEnabled(false);
        stopBtn.setEnabled(true);

        List<AuditProbeType_littlespidy> probes = auditEngine.getAllProbeTypes();
        auditEngine.runProbes(probes, target, customHeaders,
                this::onHttpLogReceived,
                this::onFindingReceived,
                this::onStatusUpdated,
                this::onExecutionComplete
        );
    }

    public void runSingleProbe(AuditProbeType_littlespidy type) {
        String target = getTargetUrl();
        if (target.isEmpty() || !target.startsWith("http")) {
            JOptionPane.showMessageDialog(this, "Please enter a valid HTTP/HTTPS GraphQL target URL.", "Target Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        runAllBtn.setEnabled(false);
        stopBtn.setEnabled(true);

        auditEngine.runProbes(Collections.singletonList(type), target, customHeaders,
                this::onHttpLogReceived,
                this::onFindingReceived,
                this::onStatusUpdated,
                this::onExecutionComplete
        );
    }

    public void stopProbes() {
        auditEngine.stop();
        statusLabel.setText("Status: Stopped by user");
        runAllBtn.setEnabled(true);
        stopBtn.setEnabled(false);
    }

    private void onHttpLogReceived(HttpLogEntry_littlespidy entry) {
        SwingUtilities.invokeLater(() -> historyTab.addLog(entry));
    }

    private void onFindingReceived(AuditFinding_littlespidy finding) {
        SwingUtilities.invokeLater(() -> {
            auditingTab.addFinding(finding);
            triggerSave();
        });
    }

    private void onStatusUpdated(String status) {
        SwingUtilities.invokeLater(() -> statusLabel.setText("Status: " + status));
    }

    private void onExecutionComplete() {
        SwingUtilities.invokeLater(() -> {
            runAllBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            statusLabel.setText("Status: Completed");
            triggerSave();
        });
    }

    private void triggerSave() {
        if (saveTrigger != null) {
            saveTrigger.accept(null);
        }
    }

    public String getTargetUrl() {
        return targetUrlField.getText().trim();
    }

    public void setTargetUrl(String url) {
        targetUrlField.setText(url != null ? url : "");
    }

    public String getCustomHeaders() {
        return customHeaders;
    }

    public void setCustomHeaders(String headers) {
        this.customHeaders = headers != null ? headers : "";
        updateHeadersButtonLabel();
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getTabTitle() {
        return tabTitle;
    }

    public void setTabTitle(String title) {
        this.tabTitle = title;
    }

    public SessionData_littlespidy exportSessionData() {
        SessionData_littlespidy data = new SessionData_littlespidy(sessionId, tabTitle, getTargetUrl());
        data.setCustomHeaders(customHeaders);
        data.setRawIntrospectionJson(voyagerTab.getCurrentIntrospectionJson());
        data.setFindings(auditingTab.getFindings());
        data.setHttpLogs(historyTab.getAllLogs());
        return data;
    }

    public void loadSessionData(SessionData_littlespidy data) {
        if (data == null) return;
        setTargetUrl(data.getTargetUrl());
        setCustomHeaders(data.getCustomHeaders());
        if (data.getFindings() != null) {
            for (AuditFinding_littlespidy f : data.getFindings()) {
                auditingTab.addFinding(f);
            }
        }
        if (data.getHttpLogs() != null) {
            for (HttpLogEntry_littlespidy l : data.getHttpLogs()) {
                historyTab.addLog(l);
            }
        }
        if (data.getRawIntrospectionJson() != null && !data.getRawIntrospectionJson().isEmpty()) {
            voyagerTab.loadOperationsIntoTree(data.getRawIntrospectionJson());
        }
    }
}
