// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.hsts.ui;

import com.littlespidy.headerinspector.ProxyHistoryCoordinator;
import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.hsts.model.HSTSEntry;
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
 * Top-level UI tab for HSTS Inspector — provides grouped HSTS pattern overview,
 * per-endpoint detail table, multi-select filters (Method / Status / Content-Type),
 * and built-in master-detail HTTP request/response editors.
 *
 * @author littlespidy
 */
public class HSTSInspectorTab extends JPanel {

    public static final String[] INSPECT_MODES = {
        HSTSDataStore.MODE_ASSESSMENT,
        HSTSDataStore.MODE_FULL,
        HSTSDataStore.MODE_MAX_AGE,
        HSTSDataStore.MODE_SUBDOMAINS,
        HSTSDataStore.MODE_PRELOAD,
        HSTSDataStore.MODE_MISSING
    };

    private final MontoyaApi api;
    private final HSTSDataStore dataStore;
    private ProxyHistoryCoordinator coordinator;

    // Summary table
    private final HSTSSummaryTableModel summaryTableModel = new HSTSSummaryTableModel();
    private final JTable summaryTable = new JTable(summaryTableModel);

    // Endpoint detail table
    private final HSTSEntryTableModel entryTableModel = new HSTSEntryTableModel();
    private final JTable entryTable = new JTable(entryTableModel);

    // Montoya editors
    private final HttpRequestEditor  requestEditor;
    private final HttpResponseEditor responseEditor;

    // ── Multi-Select Filter Buttons ───────────────────────────────────────────
    private final MultiSelectFilterButton methodFilterBtn = new MultiSelectFilterButton(
        "Method",
        List.of("All Methods", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton statusFilterBtn = new MultiSelectFilterButton(
        "Status",
        List.of("All Status Codes", "2xx Success", "200 OK", "3xx Redirection",
                "301 / 302 Redirect", "304 Not Modified", "4xx Client Error",
                "401 Unauthorized", "403 Forbidden", "404 Not Found",
                "5xx Server Error", "500 Internal Error"),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton contentTypeFilterBtn = new MultiSelectFilterButton(
        "Content-Type",
        List.of("All Content-Types", "HTML (text/html)", "JSON (application/json)",
                "JavaScript (text/javascript)", "CSS (text/css)", "XML (application/xml)",
                "Plain Text (text/plain)", "Images (image/*)", "PDF / Documents (application/pdf)"),
        sel -> refreshView()
    );

    // Other filter controls
    private final JComboBox<String> inspectModeComboBox = new JComboBox<>(INSPECT_MODES);
    private final JTextField valueFilterField          = new JTextField(14);
    private final JCheckBox inScopeOnlyCheckBox        = new JCheckBox("In-Scope Only", true);
    private final JButton loadHistoryBtn               = new JButton("Load Proxy History");
    private final JLabel statsLabel                    = new JLabel("Total Unique URLs: 0 | Patterns: 0 | Displayed: 0");
    private final JProgressBar progressBar             = new JProgressBar();

    // Debounce timer
    private final javax.swing.Timer refreshTimer;
    private volatile boolean needsRefresh = false;

    private String selectedSummaryValue = null;

    public HSTSInspectorTab(MontoyaApi api, HSTSDataStore dataStore) {
        this.api            = api;
        this.dataStore      = dataStore;
        this.requestEditor  = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout());

        this.refreshTimer = new javax.swing.Timer(350, e -> {
            if (needsRefresh) { needsRefresh = false; refreshView(); }
        });
        this.refreshTimer.setRepeats(true);
        this.refreshTimer.start();

        dataStore.addListener(() -> needsRefresh = true);

        add(createInspectorPanel(), BorderLayout.CENTER);
    }

    public void setCoordinator(ProxyHistoryCoordinator coordinator) {
        this.coordinator = coordinator;
    }

    public void cleanup() {
        if (refreshTimer != null && refreshTimer.isRunning()) refreshTimer.stop();
    }

    private JPanel createInspectorPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel top = new JPanel(new BorderLayout(5, 5));
        top.add(createMainToolbar(),   BorderLayout.NORTH);
        top.add(createStatusToolbar(), BorderLayout.SOUTH);
        panel.add(top, BorderLayout.NORTH);

        JPanel summaryPanel = new JPanel(new BorderLayout(5, 5));
        summaryPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "HSTS Value Overview & Assessment",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));
        summaryTable.setRowSorter(new TableRowSorter<>(summaryTableModel));
        summaryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupSummaryTableRendering();
        summaryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = summaryTable.getSelectedRow();
                if (row >= 0) {
                    int mr = summaryTable.convertRowIndexToModel(row);
                    selectedSummaryValue = summaryTableModel.getSummaryValueAt(mr);
                    updateEntryTable();
                }
            }
        });
        setupTableKeyboardCopy(summaryTable);
        summaryPanel.add(new JScrollPane(summaryTable), BorderLayout.CENTER);

        JPanel detailsPanel = new JPanel(new BorderLayout(5, 5));
        detailsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Endpoints Matching Selection",
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
                    HSTSEntry entry = entryTableModel.getEntryAt(mr);
                    if (entry != null) {
                        if (entry.request()  != null) requestEditor.setRequest(entry.request());
                        if (entry.response() != null) responseEditor.setResponse(entry.response());
                    }
                }
            }
        });
        setupTableKeyboardCopy(entryTable);

        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("📤 Request",  requestEditor.uiComponent());
        editorTabs.addTab("📥 Response", responseEditor.uiComponent());

        JSplitPane masterDetail = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(entryTable), editorTabs);
        masterDetail.setResizeWeight(0.55);
        detailsPanel.add(masterDetail, BorderLayout.CENTER);

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

        JLabel modeLbl = new JLabel("Inspect Mode:");
        modeLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        inspectModeComboBox.addActionListener(e -> { selectedSummaryValue = null; refreshView(); });

        JLabel filterLbl = new JLabel("Filter:");
        valueFilterField.setToolTipText("Filter by pattern value, assessment, or keyword");
        valueFilterField.addActionListener(e -> refreshView());

        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> refreshView());

        JButton resetBtn = new JButton("Reset Filters");
        resetBtn.addActionListener(e -> {
            valueFilterField.setText("");
            methodFilterBtn.clearSelection();
            statusFilterBtn.clearSelection();
            contentTypeFilterBtn.clearSelection();
            selectedSummaryValue = null;
            refreshView();
        });

        inScopeOnlyCheckBox.addActionListener(e -> refreshView());

        JButton exportTsvBtn = new JButton("Export TSV");
        exportTsvBtn.setToolTipText("Export currently displayed endpoints to clipboard as TSV");
        exportTsvBtn.addActionListener(e -> exportTsv());

        JButton clearBtn = new JButton("Clear All Data");
        clearBtn.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this,
                "Clear all captured HSTS entries?", "Clear Data", JOptionPane.YES_NO_OPTION);
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
        toolbar.add(exportTsvBtn);
        toolbar.add(clearBtn);
        return toolbar;
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
        summaryTable.getColumnModel().getColumn(2).setMaxWidth(70);
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
        entryTable.getColumnModel().getColumn(0).setMaxWidth(50);
        entryTable.getColumnModel().getColumn(1).setMaxWidth(65);
        entryTable.getColumnModel().getColumn(2).setMaxWidth(65);

        entryTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    int mr = table.convertRowIndexToModel(row);
                    HSTSEntry entry = entryTableModel.getEntryAt(mr);
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
            @Override public void actionPerformed(ActionEvent e) { copyRowsToClipboard(table); }
        });
    }

    private void copyRowsToClipboard(JTable table) {
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

    private void exportTsv() {
        List<HSTSEntry> entries = entryTableModel.getAllEntries();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No entries to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
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
        JOptionPane.showMessageDialog(this, "Copied " + entries.size() + " rows as TSV!",
            "Export Success", JOptionPane.INFORMATION_MESSAGE);
    }

    public synchronized void refreshView() {
        SwingUtilities.invokeLater(() -> {
            String mode = selectedMode();
            String kw   = valueFilterField.getText().trim();

            Set<String> methodSel  = methodFilterBtn.getSelected();
            Set<String> statusSel  = statusFilterBtn.getSelected();
            Set<String> ctSel      = contentTypeFilterBtn.getSelected();
            boolean inScope        = inScopeOnlyCheckBox.isSelected();

            java.util.function.Predicate<String> scopePred = inScope
                ? url -> api.scope().isInScope(url) : null;

            String statusStr = statusSel.isEmpty() ? "" : String.join(" / ", statusSel);

            Map<String, List<HSTSEntry>> grouped = groupWithMultiSelectCT(
                mode, kw, statusStr, ctSel, methodSel, scopePred);

            summaryTableModel.updateData(grouped);
            updateEntryTable();

            statsLabel.setText(
                "Total Unique URLs: " + dataStore.size()
                + " | Patterns: " + summaryTableModel.getRowCount()
                + " | Displayed: " + entryTableModel.getRowCount()
            );
        });
    }

    private void updateEntryTable() {
        String mode    = selectedMode();
        String kw      = valueFilterField.getText().trim();
        Set<String> ms = methodFilterBtn.getSelected();
        Set<String> ss = statusFilterBtn.getSelected();
        Set<String> cs = contentTypeFilterBtn.getSelected();
        boolean inScope = inScopeOnlyCheckBox.isSelected();

        java.util.function.Predicate<String> scopePred = inScope
            ? url -> api.scope().isInScope(url) : null;

        String statusStr = ss.isEmpty() ? "" : String.join(" / ", ss);

        List<HSTSEntry> entries;
        if (cs.size() <= 1) {
            String ctStr = cs.isEmpty() ? "" : cs.iterator().next();
            entries = dataStore.getFilteredEntries(mode, selectedSummaryValue, kw,
                statusStr, ctStr, ms, scopePred);
        } else {
            Map<Integer, HSTSEntry> merged = new LinkedHashMap<>();
            for (String ct : cs) {
                dataStore.getFilteredEntries(mode, selectedSummaryValue, kw,
                    statusStr, ct, ms, scopePred).forEach(e -> merged.putIfAbsent(e.id(), e));
            }
            entries = new ArrayList<>(merged.values());
        }
        entryTableModel.updateData(entries);
    }

    private Map<String, List<HSTSEntry>> groupWithMultiSelectCT(
            String mode, String kw,
            String statusStr, Set<String> ctSel,
            Set<String> methodSel,
            java.util.function.Predicate<String> scopePred) {

        if (ctSel.size() <= 1) {
            String ct = ctSel.isEmpty() ? "" : ctSel.iterator().next();
            return dataStore.groupByMode(mode, kw, statusStr, ct, methodSel, scopePred);
        }
        Map<String, List<HSTSEntry>> merged = new LinkedHashMap<>();
        for (String ct : ctSel) {
            dataStore.groupByMode(mode, kw, statusStr, ct, methodSel, scopePred)
                .forEach((key, list) -> {
                    merged.computeIfAbsent(key, k -> new ArrayList<>());
                    Set<Integer> seen = new HashSet<>();
                    merged.get(key).forEach(e -> seen.add(e.id()));
                    list.stream().filter(e -> seen.add(e.id())).forEach(merged.get(key)::add);
                });
        }
        return merged;
    }

    private String selectedMode() {
        Object m = inspectModeComboBox.getSelectedItem();
        return m != null ? m.toString() : HSTSDataStore.MODE_ASSESSMENT;
    }
}
