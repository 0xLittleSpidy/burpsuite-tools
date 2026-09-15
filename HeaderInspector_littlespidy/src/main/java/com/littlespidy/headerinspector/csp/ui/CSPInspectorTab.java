// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.ui;

import com.littlespidy.headerinspector.ProxyHistoryCoordinator;
import com.littlespidy.headerinspector.csp.model.CSPDataStore;
import com.littlespidy.headerinspector.csp.model.CSPEntry;
import com.littlespidy.headerinspector.csp.model.CSPParser;
import com.littlespidy.headerinspector.ui.common.MultiSelectFilterButton;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.*;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Top-level UI tab for CSP Inspector providing overview summaries, granular directive grouping,
 * fast multi-faceted triage filtering (with multi-select support), and built-in master-detail
 * HTTP request/response editors.
 *
 * @author littlespidy
 */
public class CSPInspectorTab extends JPanel {

    public static final String[] INSPECT_MODES = {
        "Full Policy",
        "All Sources (Directives)",
        "script-src",
        "default-src",
        "frame-ancestors",
        "object-src",
        "base-uri",
        "form-action",
        "style-src",
        "connect-src",
        "img-src",
        "font-src",
        "report-uri",
        "CSP-Report-Only"
    };

    private final MontoyaApi api;
    private final CSPDataStore dataStore;
    private ProxyHistoryCoordinator coordinator;

    // Summary Table Components
    private final CSPSummaryTableModel summaryTableModel = new CSPSummaryTableModel();
    private final JTable summaryTable = new JTable(summaryTableModel);

    // URL Entries Table Components
    private final CSPEntryTableModel entryTableModel = new CSPEntryTableModel();
    private final JTable entryTable = new JTable(entryTableModel);

    // Montoya Request / Response Editors
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    // ─── Multi-Select Filter Buttons ──────────────────────────────────────────
    private final MultiSelectFilterButton statusFilterBtn = new MultiSelectFilterButton(
        "Status",
        List.of(
            "All Status Codes", "2xx Success", "200 OK", "3xx Redirection",
            "301 / 302 Redirect", "304 Not Modified", "4xx Client Error",
            "401 Unauthorized", "403 Forbidden", "404 Not Found",
            "5xx Server Error", "500 Internal Error"
        ),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton contentTypeFilterBtn = new MultiSelectFilterButton(
        "Content-Type",
        List.of(
            "All Content-Types", "HTML (text/html)", "JSON (application/json)",
            "JavaScript (text/javascript)", "CSS (text/css)", "XML (application/xml)",
            "Plain Text (text/plain)", "Images (image/*)", "PDF / Documents (application/pdf)"
        ),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton methodFilterBtn = new MultiSelectFilterButton(
        "Method",
        List.of("All Methods", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"),
        sel -> refreshView()
    );

    // Filter Controls
    private final JComboBox<String> inspectModeComboBox = new JComboBox<>(INSPECT_MODES);
    private final JTextField valueFilterField = new JTextField(14);
    private final JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-Scope Only", true);
    private final JButton loadHistoryBtn = new JButton("Load Proxy History");
    private final JLabel statsLabel = new JLabel("Total Unique URLs: 0 | Patterns: 0 | Displayed URLs: 0");
    private final JProgressBar progressBar = new JProgressBar();

    // Google CSP Evaluator Panel
    private final GoogleCspEvaluatorPanel googleEvaluatorPanel = new GoogleCspEvaluatorPanel();

    // UI Debounce Timer
    private final javax.swing.Timer refreshTimer;
    private volatile boolean needsRefresh = false;

    private String selectedSummaryValue = null;

    public CSPInspectorTab(MontoyaApi api, CSPDataStore dataStore) {
        this.api = api;
        this.dataStore = dataStore;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout());

        this.refreshTimer = new javax.swing.Timer(350, e -> {
            if (needsRefresh) {
                needsRefresh = false;
                refreshView();
            }
        });
        this.refreshTimer.setRepeats(true);
        this.refreshTimer.start();

        dataStore.addListener(() -> needsRefresh = true);

        googleEvaluatorPanel.setScratchpadLauncher(this::openScratchpad);

        add(createInspectorPanel(), BorderLayout.CENTER);
    }

    public void setCoordinator(ProxyHistoryCoordinator coordinator) {
        this.coordinator = coordinator;
    }

    public void cleanup() {
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
    }

    private JPanel createInspectorPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topContainer = new JPanel(new BorderLayout(5, 5));
        topContainer.add(createMainToolbar(), BorderLayout.NORTH);
        topContainer.add(createStatusToolbar(), BorderLayout.SOUTH);
        panel.add(topContainer, BorderLayout.NORTH);

        JPanel summaryPanel = new JPanel(new BorderLayout(5, 5));
        summaryPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "CSP Policies & Directives Overview",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));

        summaryTable.setRowSorter(new TableRowSorter<>(summaryTableModel));
        summaryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        summaryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = summaryTable.getSelectedRow();
                if (row >= 0) {
                    int mr = summaryTable.convertRowIndexToModel(row);
                    selectedSummaryValue = summaryTableModel.getSummaryValueAt(mr);
                    List<CSPEntry> entries = summaryTableModel.getEntriesAt(mr);
                    if (!entries.isEmpty()) {
                        googleEvaluatorPanel.setPolicy(entries.get(0).getPrimaryCsp());
                    }
                    updateEntryTableForSelection();
                }
            }
        });
        setupTableKeyboardCopy(summaryTable);
        setupSummaryTableRendering();
        summaryPanel.add(new JScrollPane(summaryTable), BorderLayout.CENTER);

        JPanel detailsPanel = new JPanel(new BorderLayout(5, 5));
        detailsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Associated URLs",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));

        entryTable.setRowSorter(new TableRowSorter<>(entryTableModel));
        entryTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        setupEntryTableRendering();
        entryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = entryTable.getSelectedRow();
                if (row >= 0) {
                    int mr = entryTable.convertRowIndexToModel(row);
                    CSPEntry entry = entryTableModel.getEntryAt(mr);
                    if (entry != null) {
                        if (entry.request() != null) requestEditor.setRequest(entry.request());
                        if (entry.response() != null) responseEditor.setResponse(entry.response());
                        googleEvaluatorPanel.setPolicy(entry.getPrimaryCsp());
                    }
                }
            }
        });
        setupTableKeyboardCopy(entryTable);

        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("📤 Request", requestEditor.uiComponent());
        editorTabs.addTab("📥 Response", responseEditor.uiComponent());
        editorTabs.addTab("🔍 Google CSP Evaluator", googleEvaluatorPanel);

        JSplitPane masterDetailSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(entryTable), editorTabs);
        masterDetailSplit.setResizeWeight(0.55);
        detailsPanel.add(masterDetailSplit, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, summaryPanel, detailsPanel);
        mainSplit.setResizeWeight(0.35);
        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createMainToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        loadHistoryBtn.setToolTipText("Import and deduplicate requests from Burp Proxy history across all inspectors");
        loadHistoryBtn.addActionListener(e -> loadProxyHistory());

        inScopeOnlyCheckBox.setToolTipText(
            "When checked, only requests matching Burp Target Scope are loaded. " +
            "Prevents memory exhaustion and UI hangs on large Proxy histories."
        );

        JLabel modeLbl = new JLabel("Mode:");
        modeLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        inspectModeComboBox.addActionListener(e -> {
            selectedSummaryValue = null;
            refreshView();
        });

        JLabel filterLbl = new JLabel("Filter:");
        valueFilterField.setToolTipText("Filter by directive values, sources, or keywords");
        valueFilterField.addActionListener(e -> refreshView());

        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> refreshView());

        JButton resetBtn = new JButton("Reset Filters");
        resetBtn.addActionListener(e -> {
            valueFilterField.setText("");
            statusFilterBtn.clearSelection();
            contentTypeFilterBtn.clearSelection();
            methodFilterBtn.clearSelection();
            selectedSummaryValue = null;
            refreshView();
        });

        inScopeOnlyCheckBox.addActionListener(e -> refreshView());

        JButton scratchpadBtn = new JButton("🧪 Google CSP Scratchpad");
        scratchpadBtn.setToolTipText("Open interactive Google CSP Evaluator Scratchpad to test any policy");
        scratchpadBtn.addActionListener(e -> openScratchpad());

        JButton checkUpdatesBtn = new JButton("🌐 Check Engine Updates");
        checkUpdatesBtn.setToolTipText("Check for new releases from https://github.com/google/csp-evaluator");
        checkUpdatesBtn.addActionListener(e -> com.littlespidy.headerinspector.csp.evaluator.GoogleCspUpdateChecker.checkForUpdatesAsync(this));

        JButton exportTsvBtn = new JButton("Export TSV");
        exportTsvBtn.setToolTipText("Export currently displayed URL results to clipboard as TSV");
        exportTsvBtn.addActionListener(e -> exportCurrentEntriesToTsv());

        JButton clearDataBtn = new JButton("Clear All Data");
        clearDataBtn.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to clear all captured CSP entries?",
                "Clear Data", JOptionPane.YES_NO_OPTION);
            if (ok == JOptionPane.YES_OPTION) {
                dataStore.clear();
                selectedSummaryValue = null;
                refreshView();
            }
        });

        toolbar.add(loadHistoryBtn);
        toolbar.add(inScopeOnlyCheckBox);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(modeLbl);
        toolbar.add(inspectModeComboBox);
        toolbar.add(filterLbl);
        toolbar.add(valueFilterField);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(methodFilterBtn);
        toolbar.add(statusFilterBtn);
        toolbar.add(contentTypeFilterBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(applyBtn);
        toolbar.add(resetBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(scratchpadBtn);
        toolbar.add(checkUpdatesBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(exportTsvBtn);
        toolbar.add(clearDataBtn);
        return toolbar;
    }

    private void openScratchpad() {
        Window parent = SwingUtilities.getWindowAncestor(this);
        String policy = googleEvaluatorPanel.getCurrentPolicy();
        GoogleCspScratchpadDialog dialog = new GoogleCspScratchpadDialog(parent, policy);
        dialog.setVisible(true);
    }

    private JPanel createStatusToolbar() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));

        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        progressBar.setPreferredSize(new Dimension(220, 16));
        progressBar.setVisible(false);

        panel.add(statsLabel, BorderLayout.WEST);
        panel.add(progressBar, BorderLayout.EAST);
        return panel;
    }

    private void setupSummaryTableRendering() {
        summaryTable.getColumnModel().getColumn(2).setMaxWidth(70); // Count
        summaryTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected && col == 3) {
                    String str = (value != null) ? value.toString() : "";
                    if (str.startsWith("CRITICAL")) {
                        c.setForeground(new Color(180, 0, 0));
                        c.setFont(c.getFont().deriveFont(Font.BOLD));
                    } else if (str.startsWith("HIGH")) {
                        c.setForeground(new Color(200, 70, 0));
                        c.setFont(c.getFont().deriveFont(Font.BOLD));
                    } else if (str.startsWith("MEDIUM")) {
                        c.setForeground(new Color(170, 110, 0));
                    } else if (str.startsWith("GOOD")) {
                        c.setForeground(new Color(0, 120, 0));
                    } else {
                        c.setForeground(table.getForeground());
                    }
                } else if (!isSelected) {
                    c.setForeground(table.getForeground());
                }
                return c;
            }
        });
    }

    private void setupEntryTableRendering() {
        entryTable.getColumnModel().getColumn(0).setMaxWidth(50); // #
        entryTable.getColumnModel().getColumn(1).setMaxWidth(65); // Status
        entryTable.getColumnModel().getColumn(2).setMaxWidth(65); // Method

        entryTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    int mr = table.convertRowIndexToModel(row);
                    CSPEntry entry = entryTableModel.getEntryAt(mr);
                    if (entry != null) {
                        int status = entry.statusCode();
                        if      (status >= 200 && status < 300) c.setBackground(new Color(240, 255, 240));
                        else if (status >= 300 && status < 400) c.setBackground(new Color(240, 248, 255));
                        else if (status >= 400 && status < 500) c.setBackground(new Color(255, 248, 235));
                        else if (status >= 500)                 c.setBackground(new Color(255, 235, 235));
                        else                                    c.setBackground(table.getBackground());
                    }
                }
                return c;
            }
        });
    }

    private void setupTableKeyboardCopy(JTable table) {
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copy");
        table.getActionMap().put("copy", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { exportSelectedRowsToClipboard(table); }
        });
    }

    private void exportSelectedRowsToClipboard(JTable table) {
        int[] rows = table.getSelectedRows();
        if (rows.length == 0) return;
        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < table.getColumnCount(); col++)
            sb.append(table.getColumnName(col)).append(col == table.getColumnCount() - 1 ? "\n" : "\t");
        for (int row : rows)
            for (int col = 0; col < table.getColumnCount(); col++) {
                Object v = table.getValueAt(row, col);
                sb.append(v != null ? v : "").append(col == table.getColumnCount() - 1 ? "\n" : "\t");
            }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
    }

    private void exportCurrentEntriesToTsv() {
        List<CSPEntry> entries = entryTableModel.getAllEntries();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No entries currently displayed to export.",
                "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < entryTableModel.getColumnCount(); col++)
            sb.append(entryTableModel.getColumnName(col)).append(col == entryTableModel.getColumnCount() - 1 ? "\n" : "\t");
        for (int i = 0; i < entryTableModel.getRowCount(); i++)
            for (int col = 0; col < entryTableModel.getColumnCount(); col++) {
                Object v = entryTableModel.getValueAt(i, col);
                sb.append(v != null ? v : "").append(col == entryTableModel.getColumnCount() - 1 ? "\n" : "\t");
            }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        JOptionPane.showMessageDialog(this, "Copied " + entries.size() + " rows to clipboard as TSV!",
            "Export Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private void loadProxyHistory() {
        if (coordinator != null) {
            coordinator.loadAllProxyHistory(inScopeOnlyCheckBox.isSelected());
        }
    }

    public void setLoading(boolean loading, String message) {
        SwingUtilities.invokeLater(() -> {
            loadHistoryBtn.setEnabled(!loading);
            progressBar.setVisible(loading);
            progressBar.setIndeterminate(loading);
            if (message != null && !message.isBlank()) {
                statsLabel.setText(message);
            }
        });
    }

    public synchronized void refreshView() {
        SwingUtilities.invokeLater(() -> {
            String selectedMode = (String) inspectModeComboBox.getSelectedItem();
            if (selectedMode == null) selectedMode = "Full Policy";

            String filterText = valueFilterField.getText().trim();
            boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

            Set<String> methodFilter = methodFilterBtn.getSelected();
            java.util.function.Predicate<String> inScopePredicate = inScopeOnly
                ? url -> api.scope().isInScope(url)
                : null;

            final Set<String> selectedStatuses = statusFilterBtn.getSelected();
            final Set<String> selectedContentTypes = contentTypeFilterBtn.getSelected();

            Map<String, List<CSPEntry>> grouped = groupByModeWithMultiSelect(
                selectedMode, filterText, selectedStatuses, selectedContentTypes, methodFilter, inScopePredicate
            );

            summaryTableModel.updateData(grouped);
            updateEntryTableForSelection();

            int totalUnique = dataStore.size();
            int uniquePatterns = summaryTableModel.getRowCount();
            int displayedUrls = entryTableModel.getRowCount();
            statsLabel.setText(
                "Total Unique URLs: " + totalUnique +
                " | Patterns: " + uniquePatterns +
                " | Displayed URLs: " + displayedUrls
            );
        });
    }

    private Map<String, List<CSPEntry>> groupByModeWithMultiSelect(
            String mode,
            String valueFilter,
            Set<String> selectedStatuses,
            Set<String> selectedContentTypes,
            Set<String> methodFilter,
            java.util.function.Predicate<String> inScopePredicate) {

        String statusStr = selectedStatuses.isEmpty() ? "" : String.join(" / ", selectedStatuses);
        String ctStr = selectedContentTypes.isEmpty() ? "" : selectedContentTypes.iterator().next();

        if (selectedContentTypes.size() <= 1) {
            return dataStore.groupByMode(mode, valueFilter, statusStr, ctStr, methodFilter, inScopePredicate);
        }

        Map<String, List<CSPEntry>> merged = new LinkedHashMap<>();
        for (String ct : selectedContentTypes) {
            Map<String, List<CSPEntry>> partial = dataStore.groupByMode(
                mode, valueFilter, statusStr, ct, methodFilter, inScopePredicate);
            for (Map.Entry<String, List<CSPEntry>> e : partial.entrySet()) {
                merged.computeIfAbsent(e.getKey(), k -> new ArrayList<>());
                Set<Integer> existingIds = new HashSet<>();
                for (CSPEntry existing : merged.get(e.getKey())) existingIds.add(existing.id());
                for (CSPEntry candidate : e.getValue()) {
                    if (existingIds.add(candidate.id())) {
                        merged.get(e.getKey()).add(candidate);
                    }
                }
            }
        }
        return merged;
    }

    private void updateEntryTableForSelection() {
        String selectedMode = (String) inspectModeComboBox.getSelectedItem();
        if (selectedMode == null) selectedMode = "Full Policy";

        String filterText = valueFilterField.getText().trim();
        boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

        Set<String> methodFilter = methodFilterBtn.getSelected();
        Set<String> selectedStatuses = statusFilterBtn.getSelected();
        Set<String> selectedContentTypes = contentTypeFilterBtn.getSelected();

        java.util.function.Predicate<String> inScopePredicate = inScopeOnly
            ? url -> api.scope().isInScope(url)
            : null;

        String statusStr = selectedStatuses.isEmpty() ? "" : String.join(" / ", selectedStatuses);

        List<CSPEntry> entriesToShow;

        if (selectedContentTypes.size() <= 1) {
            String ctStr = selectedContentTypes.isEmpty() ? "" : selectedContentTypes.iterator().next();
            entriesToShow = dataStore.getFilteredEntries(
                selectedMode, selectedSummaryValue, filterText,
                statusStr, ctStr, methodFilter, inScopePredicate
            );
        } else {
            Map<Integer, CSPEntry> merged = new LinkedHashMap<>();
            for (String ct : selectedContentTypes) {
                List<CSPEntry> partial = dataStore.getFilteredEntries(
                    selectedMode, selectedSummaryValue, filterText,
                    statusStr, ct, methodFilter, inScopePredicate
                );
                for (CSPEntry e : partial) merged.putIfAbsent(e.id(), e);
            }
            entriesToShow = new ArrayList<>(merged.values());
        }

        entryTableModel.updateData(entriesToShow);
    }
}
