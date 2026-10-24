// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.AuditSeverity_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

public class AuditingSubTab_littlespidy extends JPanel {
    private final MontoyaApi api;
    private final Consumer<AuditProbeType_littlespidy> runSingleProbeHandler;
    private final List<AuditFinding_littlespidy> findings = new ArrayList<>();

    private final JTable findingsTable;
    private final DefaultTableModel tableModel;
    private final JTextArea descriptionArea;
    private final JTextArea recommendationArea;
    private final JTextArea impactArea;
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;

    private static final SimpleDateFormat TIME_FMT = new SimpleDateFormat("HH:mm:ss", Locale.US);

    public AuditingSubTab_littlespidy(MontoyaApi api, Consumer<AuditProbeType_littlespidy> runSingleProbeHandler) {
        super(new BorderLayout(4, 4));
        this.api = api;
        this.runSingleProbeHandler = runSingleProbeHandler;

        // Probes Button Bar
        JPanel probeButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        probeButtonsPanel.setBorder(BorderFactory.createTitledBorder("Individual Probes & Attacks"));

        addProbeButton(probeButtonsPanel, "Introspection", AuditProbeType_littlespidy.INTROSPECTION);
        addProbeButton(probeButtonsPanel, "Engine Fingerprint (InQL)", AuditProbeType_littlespidy.ENGINE_FINGERPRINT);
        addProbeButton(probeButtonsPanel, "CSRF / URL-Encoded", AuditProbeType_littlespidy.POST_CSRF);
        addProbeButton(probeButtonsPanel, "GET Queries", AuditProbeType_littlespidy.GET_METHOD);
        addProbeButton(probeButtonsPanel, "GET Mutations", AuditProbeType_littlespidy.GET_MUTATION);
        addProbeButton(probeButtonsPanel, "Tracing Mode", AuditProbeType_littlespidy.TRACE_MODE);
        addProbeButton(probeButtonsPanel, "Field Suggestions", AuditProbeType_littlespidy.FIELD_SUGGESTIONS);
        addProbeButton(probeButtonsPanel, "Directive DoS", AuditProbeType_littlespidy.DIRECTIVE_OVERLOAD);
        addProbeButton(probeButtonsPanel, "Circular DoS", AuditProbeType_littlespidy.CIRCULAR_INTROSPECTION);
        addProbeButton(probeButtonsPanel, "Field Dup DoS", AuditProbeType_littlespidy.FIELD_DUPLICATION);
        addProbeButton(probeButtonsPanel, "Alias Overload", AuditProbeType_littlespidy.ALIAS_OVERLOAD);
        addProbeButton(probeButtonsPanel, "Batch Query DoS", AuditProbeType_littlespidy.BATCH_QUERY);
        addProbeButton(probeButtonsPanel, "Unhandled Error", AuditProbeType_littlespidy.UNHANDLED_ERROR);
        addProbeButton(probeButtonsPanel, "GraphiQL Check", AuditProbeType_littlespidy.GRAPHIQL);
        addProbeButton(probeButtonsPanel, "Clairvoyance", AuditProbeType_littlespidy.CLAIRVOYANCE);

        add(probeButtonsPanel, BorderLayout.NORTH);

        // Findings table
        String[] columns = {"#", "Severity", "Title", "Category", "Target", "Discovered"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        findingsTable = new JTable(tableModel);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(70);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(260);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(140);
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(200);
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(90);

        JScrollPane tableScroll = new JScrollPane(findingsTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Discovered Vulnerabilities & Security Findings"));

        // Details Panel
        JPanel detailsPanel = new JPanel(new BorderLayout(4, 4));

        JTabbedPane infoTabs = new JTabbedPane();
        descriptionArea = createReadOnlyTextArea();
        recommendationArea = createReadOnlyTextArea();
        impactArea = createReadOnlyTextArea();

        infoTabs.addTab("Description", new JScrollPane(descriptionArea));
        infoTabs.addTab("Remediation", new JScrollPane(recommendationArea));
        infoTabs.addTab("Security Impact", new JScrollPane(impactArea));

        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();

        JSplitPane httpSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                wrapInTitled(requestViewer.uiComponent(), "Advisory Reproduction Request"),
                wrapInTitled(responseViewer.uiComponent(), "Advisory Reproduction Response"));
        httpSplit.setResizeWeight(0.5);

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, infoTabs, httpSplit);
        lowerSplit.setResizeWeight(0.35);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, lowerSplit);
        mainSplit.setResizeWeight(0.45);
        add(mainSplit, BorderLayout.CENTER);

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = findingsTable.getSelectedRow();
                if (row >= 0 && row < findings.size()) {
                    showFindingDetails(findings.get(row));
                }
            }
        });
    }

    private void addProbeButton(JPanel panel, String label, AuditProbeType_littlespidy type) {
        JButton btn = new JButton(label);
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        btn.setMargin(new Insets(2, 6, 2, 6));
        btn.addActionListener(e -> {
            if (runSingleProbeHandler != null) {
                runSingleProbeHandler.accept(type);
            }
        });
        panel.add(btn);
    }

    private JTextArea createReadOnlyTextArea() {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setLineWrap(true);
        ta.setWrapStyleWord(true);
        ta.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        ta.setBorder(new EmptyBorder(6, 6, 6, 6));
        return ta;
    }

    private JComponent wrapInTitled(Component c, String title) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    public synchronized void addFinding(AuditFinding_littlespidy finding) {
        findings.add(finding);
        int index = findings.size();
        tableModel.addRow(new Object[]{
                index,
                finding.getSeverity().getLabel(),
                finding.getTitle(),
                finding.getProbeType().getCategory(),
                finding.getEndpointUrl(),
                TIME_FMT.format(new Date(finding.getTimestamp()))
        });
        if (findings.size() == 1) {
            findingsTable.setRowSelectionInterval(0, 0);
        }
    }

    public synchronized void clearFindings() {
        findings.clear();
        tableModel.setRowCount(0);
        descriptionArea.setText("");
        recommendationArea.setText("");
        impactArea.setText("");
        requestViewer.setRequest(HttpRequest.httpRequest(""));
        responseViewer.setResponse(HttpResponse.httpResponse(""));
    }

    private void showFindingDetails(AuditFinding_littlespidy finding) {
        descriptionArea.setText(finding.getDescription());
        recommendationArea.setText(finding.getRecommendation());
        impactArea.setText(finding.getImpact());

        try {
            if (finding.getRequestBase64() != null && !finding.getRequestBase64().isEmpty()) {
                byte[] reqBytes = Base64.getDecoder().decode(finding.getRequestBase64());
                requestViewer.setRequest(HttpRequest.httpRequest(new String(reqBytes)));
            } else {
                requestViewer.setRequest(HttpRequest.httpRequest(""));
            }

            if (finding.getResponseBase64() != null && !finding.getResponseBase64().isEmpty()) {
                byte[] respBytes = Base64.getDecoder().decode(finding.getResponseBase64());
                responseViewer.setResponse(HttpResponse.httpResponse(new String(respBytes)));
            } else {
                responseViewer.setResponse(HttpResponse.httpResponse(""));
            }
        } catch (Exception ignored) {}
    }

    public List<AuditFinding_littlespidy> getFindings() {
        return new ArrayList<>(findings);
    }
}
