// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.ssoinspector.engine.OAuthActiveScanEngine;
import com.littlespidy.ssoinspector.engine.OAuthPassiveAuditEngine;
import com.littlespidy.ssoinspector.export.OAuthReportExporter;
import com.littlespidy.ssoinspector.model.*;
import com.littlespidy.ssoinspector.storage.SSOPersistentStorageManager_littlespidy;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class OAuthTab extends JPanel implements OAuthDataStore.DataStoreListener {

    private final MontoyaApi api;
    private final OAuthDataStore dataStore;
    private final OAuthActiveScanEngine activeScanEngine;
    private final SSOPersistentStorageManager_littlespidy storageManager;
    private final ExecutorService executorService;

    // UI Components
    private JTextField searchField;
    private MultiSelectFilterButton flowFilterButton;
    private MultiSelectFilterButton severityFilterButton;
    private JCheckBox autoAnalyzeCheckBox;

    private JTable requestsTable;
    private OAuthTableModel requestsTableModel;
    private TableRowSorter<OAuthTableModel> requestsTableSorter;

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    private JTable paramsTable;
    private OAuthParamTableModel paramsTableModel;

    private JTable issuesTable;
    private AuditIssueTableModel issuesTableModel;
    private JTextArea issueDetailArea;

    // Active scan attack controls
    private final Map<OAuthActiveScanEngine.AttackType, JCheckBox> attackCheckBoxes = new LinkedHashMap<>();
    private JTextField collaboratorDomainField;
    private JButton launchSelectedAttacksButton;
    private JButton launchAllAttacksButton;
    private JProgressBar scanProgressBar;
    private JTextArea scanLogArea;

    private OAuthRequestEntry currentSelectedEntry;

    public OAuthTab(MontoyaApi api, OAuthDataStore dataStore, OAuthActiveScanEngine activeScanEngine) {
        this(api, dataStore, activeScanEngine, null);
    }

    public OAuthTab(MontoyaApi api, OAuthDataStore dataStore, OAuthActiveScanEngine activeScanEngine, SSOPersistentStorageManager_littlespidy storageManager) {
        this.api = api;
        this.dataStore = dataStore;
        this.activeScanEngine = activeScanEngine;
        this.storageManager = storageManager;
        this.executorService = Executors.newSingleThreadExecutor();

        setLayout(new BorderLayout());
        buildUI();

        dataStore.addListener(this);
    }

    private void buildUI() {
        // 1. Top Control Bar
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        topBar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        topBar.add(new JLabel("Filter:"));
        searchField = new JTextField(15);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { refreshFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { refreshFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { refreshFilter(); }
        });
        topBar.add(searchField);

        List<String> flowOptions = new ArrayList<>();
        flowOptions.add("All Flows");
        for (OAuthFlowType ft : OAuthFlowType.values()) {
            flowOptions.add(ft.getDisplayName());
        }
        flowFilterButton = new MultiSelectFilterButton("Flow", flowOptions, sel -> refreshFilter());
        topBar.add(flowFilterButton);

        List<String> severityOptions = Arrays.asList("All Severities", "High", "Medium", "Low", "Information", "Clean");
        severityFilterButton = new MultiSelectFilterButton("Severity", severityOptions, sel -> refreshFilter());
        topBar.add(severityFilterButton);

        JButton runPassiveButton = new JButton("Run Passive Audit");
        runPassiveButton.addActionListener(e -> runPassiveAuditOnSelected());
        topBar.add(runPassiveButton);

        launchAllAttacksButton = new JButton("Run All Active Checks");
        launchAllAttacksButton.addActionListener(e -> runAllActiveChecksOnSelected());
        topBar.add(launchAllAttacksButton);

        JButton clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Are you sure you want to clear all captured OAuth requests?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                dataStore.clear();
                if (storageManager != null) {
                    storageManager.scheduleAutoSave();
                }
            }
        });
        topBar.add(clearButton);

        JButton exportButton = new JButton("Export Report");
        exportButton.addActionListener(e -> exportReport());
        topBar.add(exportButton);

        autoAnalyzeCheckBox = new JCheckBox("Auto-analyze on send", true);
        topBar.add(autoAnalyzeCheckBox);

        JPanel headerStack = new JPanel(new BorderLayout());
        if (storageManager != null) {
            headerStack.add(storageManager.createSessionToolbarComponent(this, this::refreshFilter), BorderLayout.NORTH);
            headerStack.add(topBar, BorderLayout.SOUTH);
            add(headerStack, BorderLayout.NORTH);
        } else {
            add(topBar, BorderLayout.NORTH);
        }

        // 2. Master-Detail Split Pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.40);

        // Top Table (OAuth Requests)
        requestsTableModel = new OAuthTableModel();
        requestsTable = new JTable(requestsTableModel);
        requestsTableSorter = new TableRowSorter<>(requestsTableModel);
        requestsTableSorter.setSortsOnUpdates(true);
        requestsTable.setRowSorter(requestsTableSorter);
        requestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

        // Setup custom renderer for Severity column
        SeverityCellRenderer severityRenderer = new SeverityCellRenderer();
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_SEVERITY).setCellRenderer(severityRenderer);

        // Adjust column widths
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_ID).setPreferredWidth(45);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_TIME).setPreferredWidth(75);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_METHOD).setPreferredWidth(65);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_HOST).setPreferredWidth(160);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_PATH).setPreferredWidth(220);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_FLOW).setPreferredWidth(140);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_SEVERITY).setPreferredWidth(85);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_ISSUES_COUNT).setPreferredWidth(60);
        requestsTable.getColumnModel().getColumn(OAuthTableModel.COL_ISSUE_SUMMARY).setPreferredWidth(300);

        requestsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                handleRowSelected();
            }
        });

        JScrollPane tableScroll = new JScrollPane(requestsTable);
        splitPane.setTopComponent(tableScroll);

        // Bottom Detail Tabs
        JTabbedPane detailTabs = new JTabbedPane();

        // Sub-tab 1: Request
        requestEditor = api.userInterface().createHttpRequestEditor();
        detailTabs.addTab("Request", requestEditor.uiComponent());

        // Sub-tab 2: Response
        responseEditor = api.userInterface().createHttpResponseEditor();
        detailTabs.addTab("Response", responseEditor.uiComponent());

        // Sub-tab 3: OAuth Parameters Table
        paramsTableModel = new OAuthParamTableModel();
        paramsTable = new JTable(paramsTableModel);
        paramsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        paramsTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        paramsTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        paramsTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        paramsTable.getColumnModel().getColumn(3).setPreferredWidth(250);
        paramsTable.getColumnModel().getColumn(4).setPreferredWidth(90);
        paramsTable.getColumnModel().getColumn(5).setPreferredWidth(250);
        detailTabs.addTab("OAuth Parameters", new JScrollPane(paramsTable));

        // Sub-tab 4: Security Audit Details
        JPanel auditPanel = new JPanel(new BorderLayout());
        issuesTableModel = new AuditIssueTableModel();
        issuesTable = new JTable(issuesTableModel);
        issuesTable.getColumnModel().getColumn(0).setCellRenderer(new SeverityCellRenderer());
        issuesTable.getColumnModel().getColumn(0).setPreferredWidth(100);
        issuesTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        issuesTable.getColumnModel().getColumn(2).setPreferredWidth(350);
        issuesTable.getColumnModel().getColumn(3).setPreferredWidth(120);

        issueDetailArea = new JTextArea();
        issueDetailArea.setEditable(false);
        issueDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        issueDetailArea.setLineWrap(true);
        issueDetailArea.setWrapStyleWord(true);

        issuesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = issuesTable.getSelectedRow();
                if (selectedRow >= 0) {
                    SSOAuditIssue issue = issuesTableModel.getIssueAt(selectedRow);
                    if (issue != null) {
                        displayIssueDetail(issue);
                    }
                }
            }
        });

        JSplitPane auditSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(issuesTable), new JScrollPane(issueDetailArea));
        auditSplit.setResizeWeight(0.5);
        auditPanel.add(auditSplit, BorderLayout.CENTER);
        detailTabs.addTab("Security Audit", auditPanel);

        // Sub-tab 5: Active Attack Launcher Panel
        JPanel attackLauncherPanel = buildActiveAttackLauncherPanel();
        detailTabs.addTab("Active Scanner", attackLauncherPanel);

        splitPane.setBottomComponent(detailTabs);
        add(splitPane, BorderLayout.CENTER);
    }

    private JPanel buildActiveAttackLauncherPanel() {
        JPanel main = new JPanel(new BorderLayout(6, 6));
        main.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // Top settings bar
        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        configPanel.add(new JLabel("Collaborator / Callback Domain:"));
        collaboratorDomainField = new JTextField(25);
        collaboratorDomainField.setText("burpcollaborator.net");
        configPanel.add(collaboratorDomainField);

        JButton selectAllBtn = new JButton("Select All Attacks");
        selectAllBtn.addActionListener(e -> attackCheckBoxes.values().forEach(cb -> cb.setSelected(true)));
        configPanel.add(selectAllBtn);

        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> attackCheckBoxes.values().forEach(cb -> cb.setSelected(false)));
        configPanel.add(deselectAllBtn);

        launchSelectedAttacksButton = new JButton("Launch Selected Attacks");
        launchSelectedAttacksButton.addActionListener(e -> launchSelectedAttacks());
        configPanel.add(launchSelectedAttacksButton);

        main.add(configPanel, BorderLayout.NORTH);

        // Center attacks checklist grid
        JPanel checklistGrid = new JPanel(new GridLayout(0, 2, 6, 4));
        checklistGrid.setBorder(BorderFactory.createTitledBorder("Modular Attack Selection"));

        for (OAuthActiveScanEngine.AttackType type : OAuthActiveScanEngine.AttackType.values()) {
            JCheckBox cb = new JCheckBox(type.getLabel(), true);
            cb.setToolTipText(type.getDescription());
            attackCheckBoxes.put(type, cb);
            checklistGrid.add(cb);
        }

        // Bottom log console & progress bar
        JPanel logPanel = new JPanel(new BorderLayout(4, 4));
        logPanel.setBorder(BorderFactory.createTitledBorder("Active Scan Execution Log"));

        scanProgressBar = new JProgressBar();
        scanProgressBar.setStringPainted(true);
        scanProgressBar.setString("Ready");
        logPanel.add(scanProgressBar, BorderLayout.NORTH);

        scanLogArea = new JTextArea(8, 40);
        scanLogArea.setEditable(false);
        scanLogArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logPanel.add(new JScrollPane(scanLogArea), BorderLayout.CENTER);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, checklistGrid, logPanel);
        centerSplit.setResizeWeight(0.4);
        main.add(centerSplit, BorderLayout.CENTER);

        return main;
    }

    private void handleRowSelected() {
        int viewRow = requestsTable.getSelectedRow();
        if (viewRow < 0) {
            clearDetails();
            return;
        }

        int modelRow = requestsTable.convertRowIndexToModel(viewRow);
        OAuthRequestEntry entry = requestsTableModel.getEntryAt(modelRow);
        if (entry == null) {
            clearDetails();
            return;
        }

        currentSelectedEntry = entry;

        // Set request and response editors
        if (entry.getOriginalRequestResponse() != null) {
            if (entry.getOriginalRequestResponse().request() != null) {
                requestEditor.setRequest(entry.getOriginalRequestResponse().request());
            }
            if (entry.getOriginalRequestResponse().hasResponse() && entry.getOriginalRequestResponse().response() != null) {
                responseEditor.setResponse(entry.getOriginalRequestResponse().response());
            }
        }

        // Set parameters table
        paramsTableModel.setParameters(entry.getParameters());

        // Set issues table
        issuesTableModel.setIssues(entry.getIssues());
        if (!entry.getIssues().isEmpty()) {
            issuesTable.setRowSelectionInterval(0, 0);
            displayIssueDetail(entry.getIssues().get(0));
        } else {
            issueDetailArea.setText("No security issues detected for this request.");
        }
    }

    private void displayIssueDetail(SSOAuditIssue issue) {
        StringBuilder sb = new StringBuilder();
        sb.append("=================================================================\n");
        sb.append("ISSUE: ").append(issue.getTitle()).append("\n");
        sb.append("SEVERITY: ").append(issue.getSeverity().getLabel()).append("\n");
        sb.append("CONFIDENCE: ").append(issue.getConfidence().getLabel()).append("\n");
        sb.append("TYPE: ").append(issue.isActiveProbe() ? "Active Probe" : "Passive Audit").append("\n");
        sb.append("=================================================================\n\n");
        sb.append("DESCRIPTION:\n").append(issue.getDescription()).append("\n\n");
        sb.append("REMEDIATION:\n").append(issue.getRemediation()).append("\n\n");
        if (!issue.getReferences().isBlank()) {
            sb.append("REFERENCES:\n").append(issue.getReferences()).append("\n");
        }
        issueDetailArea.setText(sb.toString());
        issueDetailArea.setCaretPosition(0);
    }

    private void clearDetails() {
        currentSelectedEntry = null;
        paramsTableModel.setParameters(Collections.emptyList());
        issuesTableModel.setIssues(Collections.emptyList());
        issueDetailArea.setText("");
    }

    private void refreshFilter() {
        String text = searchField.getText();
        Set<String> flowFilters = flowFilterButton.getSelected();
        Set<String> sevFilters = severityFilterButton.getSelected();

        List<OAuthRequestEntry> filtered = dataStore.getFilteredEntries(text, flowFilters, sevFilters);
        requestsTableModel.setEntries(filtered);
    }

    private void runPassiveAuditOnSelected() {
        if (currentSelectedEntry == null) {
            JOptionPane.showMessageDialog(this, "Please select an OAuth request from the table first.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<SSOAuditIssue> newIssues = OAuthPassiveAuditEngine.audit(
                currentSelectedEntry.getOriginalRequestResponse(),
                currentSelectedEntry.getParameters(),
                currentSelectedEntry.getFlowType()
        );

        for (SSOAuditIssue issue : newIssues) {
            currentSelectedEntry.addIssue(issue);
        }

        dataStore.notifyUpdated(currentSelectedEntry);
        issuesTableModel.setIssues(currentSelectedEntry.getIssues());
        handleRowSelected();
    }

    private void runAllActiveChecksOnSelected() {
        if (currentSelectedEntry == null) {
            JOptionPane.showMessageDialog(this, "Please select an OAuth request from the table first.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        attackCheckBoxes.values().forEach(cb -> cb.setSelected(true));
        launchSelectedAttacks();
    }

    private void launchSelectedAttacks() {
        if (currentSelectedEntry == null) {
            JOptionPane.showMessageDialog(this, "Please select an OAuth request from the table first.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Set<OAuthActiveScanEngine.AttackType> selectedAttacks = EnumSet.noneOf(OAuthActiveScanEngine.AttackType.class);
        for (Map.Entry<OAuthActiveScanEngine.AttackType, JCheckBox> entry : attackCheckBoxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedAttacks.add(entry.getKey());
            }
        }

        if (selectedAttacks.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select at least one attack from the checklist.", "No Attacks Selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String domain = collaboratorDomainField.getText().trim();
        OAuthRequestEntry target = currentSelectedEntry;

        launchSelectedAttacksButton.setEnabled(false);
        launchAllAttacksButton.setEnabled(false);
        scanProgressBar.setIndeterminate(true);
        scanProgressBar.setString("Running active probes...");
        scanLogArea.setText("");

        executorService.submit(() -> {
            try {
                List<SSOAuditIssue> detected = activeScanEngine.runAttacks(
                        target,
                        selectedAttacks,
                        domain,
                        msg -> SwingUtilities.invokeLater(() -> {
                            scanLogArea.append(msg + "\n");
                            scanLogArea.setCaretPosition(scanLogArea.getDocument().getLength());
                        })
                );

                for (SSOAuditIssue issue : detected) {
                    target.addIssue(issue);
                }

                SwingUtilities.invokeLater(() -> {
                    dataStore.notifyUpdated(target);
                    if (currentSelectedEntry == target) {
                        issuesTableModel.setIssues(target.getIssues());
                        handleRowSelected();
                    }
                    scanProgressBar.setIndeterminate(false);
                    scanProgressBar.setString("Completed (" + detected.size() + " findings)");
                    launchSelectedAttacksButton.setEnabled(true);
                    launchAllAttacksButton.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    scanLogArea.append("Active scan error: " + ex.getMessage() + "\n");
                    scanProgressBar.setIndeterminate(false);
                    scanProgressBar.setString("Error");
                    launchSelectedAttacksButton.setEnabled(true);
                    launchAllAttacksButton.setEnabled(true);
                });
            }
        });
    }

    private void exportReport() {
        List<OAuthRequestEntry> entries = dataStore.getAllEntries();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No captured requests to export.", "Empty Store", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = {"Markdown (.md)", "JSON (.json)", "Cancel"};
        int choice = JOptionPane.showOptionDialog(this, "Select export format:", "Export Audit Report",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        if (choice == 0) {
            String md = OAuthReportExporter.exportToMarkdown(entries);
            copyToClipboardOrShow(md, "Markdown Report");
        } else if (choice == 1) {
            String json = OAuthReportExporter.exportToJson(entries);
            copyToClipboardOrShow(json, "JSON Report");
        }
    }

    private void copyToClipboardOrShow(String content, String title) {
        StringSelection selection = new StringSelection(content);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);

        JTextArea area = new JTextArea(content, 20, 60);
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setCaretPosition(0);

        JOptionPane.showMessageDialog(this, new JScrollPane(area), title + " (Copied to Clipboard)", JOptionPane.INFORMATION_MESSAGE);
    }

    public boolean isAutoAnalyzeEnabled() {
        return autoAnalyzeCheckBox.isSelected();
    }

    public void selectEntry(OAuthRequestEntry entry) {
        if (entry == null) return;
        for (int i = 0; i < requestsTable.getRowCount(); i++) {
            int modelRow = requestsTable.convertRowIndexToModel(i);
            if (requestsTableModel.getEntryAt(modelRow) == entry) {
                requestsTable.setRowSelectionInterval(i, i);
                requestsTable.scrollRectToVisible(requestsTable.getCellRect(i, 0, true));
                break;
            }
        }
    }

    @Override
    public void onEntryAdded(OAuthRequestEntry entry) {
        if (storageManager != null) {
            storageManager.scheduleAutoSave();
        }
        SwingUtilities.invokeLater(() -> {
            refreshFilter();
            selectEntry(entry);
        });
    }

    @Override
    public void onEntryUpdated(OAuthRequestEntry entry) {
        if (storageManager != null) {
            storageManager.scheduleAutoSave();
        }
        SwingUtilities.invokeLater(() -> {
            int selected = requestsTable.getSelectedRow();
            refreshFilter();
            if (selected >= 0 && selected < requestsTable.getRowCount()) {
                requestsTable.setRowSelectionInterval(selected, selected);
            }
        });
    }

    @Override
    public void onStoreCleared() {
        if (storageManager != null) {
            storageManager.scheduleAutoSave();
        }
        SwingUtilities.invokeLater(() -> {
            requestsTableModel.setEntries(Collections.emptyList());
            clearDetails();
            scanLogArea.setText("");
            scanProgressBar.setString("Ready");
        });
    }
}
