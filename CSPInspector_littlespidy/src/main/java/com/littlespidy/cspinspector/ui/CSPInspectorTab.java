// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.ui;

import com.littlespidy.cspinspector.model.CSPDataStore;
import com.littlespidy.cspinspector.model.CSPEntry;
import com.littlespidy.cspinspector.model.CSPParser;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
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
import java.time.ZonedDateTime;
import java.util.*;
import java.util.List;

/**
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

    private final JTabbedPane rootTabbedPane = new JTabbedPane();

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
            "All Status Codes",
            "2xx Success",
            "200 OK",
            "3xx Redirection",
            "301 / 302 Redirect",
            "304 Not Modified",
            "4xx Client Error",
            "401 Unauthorized",
            "403 Forbidden",
            "404 Not Found",
            "5xx Server Error",
            "500 Internal Error"
        ),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton contentTypeFilterBtn = new MultiSelectFilterButton(
        "Content-Type",
        List.of(
            "All Content-Types",
            "HTML (text/html)",
            "JSON (application/json)",
            "JavaScript (text/javascript)",
            "CSS (text/css)",
            "XML (application/xml)",
            "Plain Text (text/plain)",
            "Images (image/*)",
            "PDF / Documents (application/pdf)"
        ),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton methodFilterBtn = new MultiSelectFilterButton(
        "Method",
        List.of(
            "All Methods",
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "HEAD"
        ),
        sel -> refreshView()
    );
    // ─────────────────────────────────────────────────────────────────────────

    // Filter Controls
    private final JComboBox<String> inspectModeComboBox = new JComboBox<>(INSPECT_MODES);
    private final JTextField valueFilterField = new JTextField(14);
    private final JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-Scope Only", false);
    private final JLabel statsLabel = new JLabel("Total Unique URLs: 0 | Patterns: 0 | Displayed URLs: 0");

    // UI Debounce Timer
    private final javax.swing.Timer refreshTimer;
    private volatile boolean needsRefresh = false;

    // Selected summary pattern
    private String selectedSummaryValue = null;

    public CSPInspectorTab(MontoyaApi api, CSPDataStore dataStore) {
        this.api = api;
        this.dataStore = dataStore;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout());

        // Debounce timer (350ms)
        this.refreshTimer = new javax.swing.Timer(350, e -> {
            if (needsRefresh) {
                needsRefresh = false;
                refreshView();
            }
        });
        this.refreshTimer.setRepeats(true);
        this.refreshTimer.start();

        dataStore.addListener(() -> needsRefresh = true);

        // Tab 1: Welcome & Guide
        rootTabbedPane.addTab("Welcome & Guide", createWelcomePanel());

        // Tab 2: CSP Inspector
        rootTabbedPane.addTab("CSP Inspector", createInspectorPanel());

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void cleanup() {
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
    }

    private JComponent createWelcomePanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        JLabel titleLabel = new JLabel("Content Security Policy (CSP) Inspector");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setText(
            "CSP Inspector is an interactive analysis tool for Burp Suite designed to rapidly audit, group, "
                + "and analyze Content Security Policy implementations across target applications.\n\n"
                + "Identify missing CSP protection, dangerous source expressions ('unsafe-inline', 'unsafe-eval', wildcard domains), "
                + "Clickjacking risks (missing frame-ancestors), plugin injection surfaces (missing object-src), "
                + "and Report-Only test configurations in seconds."
        );

        JPanel headerPanel = new JPanel(new BorderLayout(5, 10));
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);

        JPanel cardsPanel = new JPanel(new GridLayout(0, 2, 20, 20));
        cardsPanel.add(createCard(
            "1. On-Demand Ingestion & Deduplication",
            "Import target traffic from Burp Proxy history on-demand via 'Load Proxy History'. "
                + "Endpoints are automatically deduplicated by Method + URL to prevent table clutter."
        ));
        cardsPanel.add(createCard(
            "2. Multi-Mode Directive Breakdown",
            "Analyze policies by Full CSP string, by individual directives (script-src, frame-ancestors, object-src, etc.), "
                + "or by specific source tokens ('unsafe-inline', 'unsafe-eval', data:, https://*)."
        ));
        cardsPanel.add(createCard(
            "3. Multi-Select Triage Filters & Preset Chips",
            "Filter instantly by HTTP Method, Status Code, and Content-Type using multi-select dropdowns. "
                + "Select multiple values at once (e.g. GET + POST). Use one-click quick chips for immediate vulnerability identification."
        ));
        cardsPanel.add(createCard(
            "4. Integrated Master-Detail Viewer",
            "Click any URL row to view the full, raw HTTP request and response in Burp's native Pretty/Raw/Hex editors."
        ));

        panel.add(headerPanel, BorderLayout.NORTH);
        panel.add(cardsPanel, BorderLayout.CENTER);

        return new JScrollPane(panel);
    }

    private JPanel createCard(String title, String description) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(200, 200, 200), 1, true),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 15));

        JTextArea desc = new JTextArea(description);
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(desc, BorderLayout.CENTER);
        return card;
    }

    private JPanel createInspectorPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top Toolbars
        JPanel topContainer = new JPanel(new BorderLayout(5, 5));
        topContainer.add(createMainToolbar(), BorderLayout.NORTH);
        topContainer.add(createQuickFilterToolbar(), BorderLayout.SOUTH);
        panel.add(topContainer, BorderLayout.NORTH);

        // Center Workspaces
        // Top: Summary Table
        JPanel summaryPanel = new JPanel(new BorderLayout(5, 5));
        summaryPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "CSP Value Overview & Assessment",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));

        summaryTable.setRowSorter(new TableRowSorter<>(summaryTableModel));
        summaryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupSummaryTableRendering();
        summaryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = summaryTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = summaryTable.convertRowIndexToModel(row);
                    selectedSummaryValue = summaryTableModel.getSummaryValueAt(modelRow);
                    updateEntryTableForSelection();
                }
            }
        });
        setupTableKeyboardCopy(summaryTable);
        summaryPanel.add(new JScrollPane(summaryTable), BorderLayout.CENTER);

        // Bottom: URL Entries Table + Montoya Editors (Master-Detail)
        JPanel detailsPanel = new JPanel(new BorderLayout(5, 5));
        detailsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Associated Endpoints",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));

        entryTable.setRowSorter(new TableRowSorter<>(entryTableModel));
        entryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupEntryTableRendering();
        entryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = entryTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = entryTable.convertRowIndexToModel(row);
                    CSPEntry entry = entryTableModel.getEntryAt(modelRow);
                    if (entry != null) {
                        if (entry.request() != null) requestEditor.setRequest(entry.request());
                        if (entry.response() != null) responseEditor.setResponse(entry.response());
                    }
                }
            }
        });
        setupTableKeyboardCopy(entryTable);

        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Request", requestEditor.uiComponent());
        editorTabs.addTab("Response", responseEditor.uiComponent());

        JSplitPane masterDetailSplit = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(entryTable),
            editorTabs
        );
        masterDetailSplit.setResizeWeight(0.55);
        detailsPanel.add(masterDetailSplit, BorderLayout.CENTER);

        // Main Vertical Split
        JSplitPane mainSplit = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            summaryPanel,
            detailsPanel
        );
        mainSplit.setResizeWeight(0.38);
        panel.add(mainSplit, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createMainToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton loadHistoryBtn = new JButton("Load Proxy History");
        loadHistoryBtn.setToolTipText("Import and deduplicate requests and responses from Burp Proxy history");
        loadHistoryBtn.addActionListener(e -> loadProxyHistory());

        JLabel modeLbl = new JLabel("Inspect Mode:");
        modeLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));

        inspectModeComboBox.addActionListener(e -> {
            selectedSummaryValue = null;
            refreshView();
        });

        JLabel filterLbl = new JLabel("Keyword:");
        valueFilterField.setToolTipText("Filter policy or directive values (e.g. unsafe-inline, data:, none, report-uri)");
        valueFilterField.addActionListener(e -> refreshView());

        // Tooltips for multi-select filter buttons
        statusFilterBtn.setToolTipText("Multi-select HTTP status codes to filter by");
        contentTypeFilterBtn.setToolTipText("Multi-select Content-Types to filter by");
        methodFilterBtn.setToolTipText("Multi-select HTTP methods to filter by (GET, POST, PUT, etc.)");

        JButton applyFilterBtn = new JButton("Apply");
        applyFilterBtn.addActionListener(e -> refreshView());

        JButton clearFilterBtn = new JButton("Reset Filters");
        clearFilterBtn.addActionListener(e -> {
            valueFilterField.setText("");
            statusFilterBtn.clearSelection();
            contentTypeFilterBtn.clearSelection();
            methodFilterBtn.clearSelection();
            selectedSummaryValue = null;
            refreshView();
        });

        inScopeOnlyCheckBox.addActionListener(e -> refreshView());

        JButton exportTsvBtn = new JButton("Export TSV");
        exportTsvBtn.setToolTipText("Export currently displayed URL results to system clipboard as TSV");
        exportTsvBtn.addActionListener(e -> exportCurrentEntriesToTsv());

        JButton clearDataBtn = new JButton("Clear All Data");
        clearDataBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to clear all captured CSP entries?",
                "Clear Data",
                JOptionPane.YES_NO_OPTION
            );
            if (confirm == JOptionPane.YES_OPTION) {
                dataStore.clear();
                selectedSummaryValue = null;
                refreshView();
            }
        });

        toolbar.add(loadHistoryBtn);
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
        toolbar.add(applyFilterBtn);
        toolbar.add(clearFilterBtn);
        toolbar.add(inScopeOnlyCheckBox);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(exportTsvBtn);
        toolbar.add(clearDataBtn);

        return toolbar;
    }

    private JPanel createQuickFilterToolbar() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JPanel chipsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JLabel quickLbl = new JLabel("Quick Presets:");
        quickLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        chipsPanel.add(quickLbl);

        String[] quickPresets = {
            "'unsafe-inline'", "'unsafe-eval'", "data:", "*", "(missing CSP)", "CSP-Report-Only", "frame-ancestors 'none'", "object-src 'none'"
        };

        for (String preset : quickPresets) {
            JButton chip = new JButton(preset);
            chip.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            chip.setMargin(new Insets(1, 6, 1, 6));
            chip.addActionListener(e -> {
                if (preset.equals("CSP-Report-Only")) {
                    inspectModeComboBox.setSelectedItem("CSP-Report-Only");
                    valueFilterField.setText("");
                } else if (preset.equals("frame-ancestors 'none'")) {
                    inspectModeComboBox.setSelectedItem("frame-ancestors");
                    valueFilterField.setText("'none'");
                } else if (preset.equals("object-src 'none'")) {
                    inspectModeComboBox.setSelectedItem("object-src");
                    valueFilterField.setText("'none'");
                } else {
                    inspectModeComboBox.setSelectedItem("Full Policy");
                    valueFilterField.setText(preset);
                }
                selectedSummaryValue = null;
                refreshView();
            });
            chipsPanel.add(chip);
        }

        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 2));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        statsPanel.add(statsLabel);

        panel.add(chipsPanel, BorderLayout.WEST);
        panel.add(statsPanel, BorderLayout.EAST);

        return panel;
    }

    private void setupSummaryTableRendering() {
        summaryTable.getColumnModel().getColumn(1).setMaxWidth(80); // Count

        summaryTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
            ) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                int modelRow = table.convertRowIndexToModel(row);
                Object assessmentObj = summaryTableModel.getValueAt(modelRow, 2);
                String assessment = assessmentObj != null ? assessmentObj.toString() : "";

                if (!isSelected) {
                    if (assessment.startsWith("CRITICAL") || assessment.startsWith("HIGH")) {
                        c.setBackground(new Color(255, 230, 230)); // light red
                    } else if (assessment.startsWith("MEDIUM")) {
                        c.setBackground(new Color(255, 245, 220)); // light yellow/orange
                    } else if (assessment.startsWith("GOOD")) {
                        c.setBackground(new Color(235, 255, 235)); // light green
                    } else {
                        c.setBackground(table.getBackground());
                    }
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
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
            ) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                int modelRow = table.convertRowIndexToModel(row);
                CSPEntry entry = entryTableModel.getEntryAt(modelRow);

                if (entry != null && !isSelected) {
                    int status = entry.statusCode();
                    if (status >= 200 && status < 300) {
                        c.setBackground(new Color(240, 255, 240)); // light green
                    } else if (status >= 300 && status < 400) {
                        c.setBackground(new Color(240, 248, 255)); // light blue
                    } else if (status >= 400 && status < 500) {
                        c.setBackground(new Color(255, 248, 235)); // light orange
                    } else if (status >= 500) {
                        c.setBackground(new Color(255, 235, 235)); // light red
                    } else {
                        c.setBackground(table.getBackground());
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
            @Override
            public void actionPerformed(ActionEvent e) {
                exportSelectedRowsToClipboard(table);
            }
        });
    }

    private void exportSelectedRowsToClipboard(JTable table) {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) return;

        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < table.getColumnCount(); col++) {
            sb.append(table.getColumnName(col)).append(col == table.getColumnCount() - 1 ? "\n" : "\t");
        }
        for (int row : selectedRows) {
            for (int col = 0; col < table.getColumnCount(); col++) {
                Object val = table.getValueAt(row, col);
                sb.append(val != null ? val.toString() : "").append(col == table.getColumnCount() - 1 ? "\n" : "\t");
            }
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
    }

    private void exportCurrentEntriesToTsv() {
        List<CSPEntry> entries = entryTableModel.getAllEntries();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No entries currently displayed to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < entryTableModel.getColumnCount(); col++) {
            sb.append(entryTableModel.getColumnName(col)).append(col == entryTableModel.getColumnCount() - 1 ? "\n" : "\t");
        }

        for (int i = 0; i < entryTableModel.getRowCount(); i++) {
            for (int col = 0; col < entryTableModel.getColumnCount(); col++) {
                Object val = entryTableModel.getValueAt(i, col);
                sb.append(val != null ? val.toString() : "").append(col == entryTableModel.getColumnCount() - 1 ? "\n" : "\t");
            }
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        JOptionPane.showMessageDialog(this, "Copied " + entries.size() + " rows to clipboard as TSV!", "Export Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private void loadProxyHistory() {
        SwingWorker<List<CSPEntry>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<CSPEntry> doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                Map<String, CSPEntry> uniqueEntries = new LinkedHashMap<>();
                boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

                for (ProxyHttpRequestResponse item : history) {
                    if (!item.hasResponse()) continue;

                    String url = item.request().url();
                    if (inScopeOnly && !api.scope().isInScope(url)) {
                        continue;
                    }

                    var resp = item.response();
                    String host = item.request().httpService() != null ? item.request().httpService().host() : "";
                    String path = item.request().path() != null ? item.request().path() : "/";
                    String method = item.request().method() != null ? item.request().method().toUpperCase() : "GET";
                    String dedupeKey = method + " " + url;

                    String csp = resp.headerValue("Content-Security-Policy");
                    String cspRo = resp.headerValue("Content-Security-Policy-Report-Only");
                    String xCsp = resp.headerValue("X-Content-Security-Policy");
                    String xWebKit = resp.headerValue("X-WebKit-CSP");

                    String effectivePolicy = (csp != null && !csp.isEmpty()) ? csp : cspRo;
                    Map<String, List<String>> parsedDirectives = CSPParser.parsePolicy(effectivePolicy);

                    CSPEntry entry = new CSPEntry(
                        dataStore.nextId(),
                        url,
                        host,
                        path,
                        method,
                        resp.statusCode(),
                        resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "",
                        csp != null ? csp : "",
                        cspRo != null ? cspRo : "",
                        xCsp != null ? xCsp : "",
                        xWebKit != null ? xWebKit : "",
                        parsedDirectives,
                        item.request(),
                        resp,
                        ZonedDateTime.now()
                    );
                    uniqueEntries.put(dedupeKey, entry);
                }
                return new ArrayList<>(uniqueEntries.values());
            }

            @Override
            protected void done() {
                try {
                    List<CSPEntry> result = get();
                    dataStore.addEntries(result);
                    refreshView();
                    JOptionPane.showMessageDialog(
                        CSPInspectorTab.this,
                        "Successfully imported " + result.size() + " unique URLs from Proxy history.",
                        "Import Complete",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    api.logging().logToError("Error loading proxy history in CSPInspector: " + ex.getMessage());
                }
            }
        };

        worker.execute();
    }

    // ── Filter Accessors ────────────────────────────────────────────────────

    /**
     * Translates multi-select status button selections into the status filter string
     * understood by {@link CSPDataStore#matchesStatusCode}.
     * When nothing is selected the method returns an empty string ("all pass").
     */
    private String getStatusFilterString() {
        Set<String> sel = statusFilterBtn.getSelected();
        if (sel.isEmpty()) return "";
        // Join multiple selections with " / " so matchesStatusCode can tokenise them
        return String.join(" / ", sel);
    }

    /**
     * Translates multi-select content-type button selections into a single filter
     * string for {@link CSPDataStore#matchesContentType}.
     * When nothing is selected returns empty string ("all pass").
     */
    private String getContentTypeFilterString() {
        Set<String> sel = contentTypeFilterBtn.getSelected();
        if (sel.isEmpty()) return "";
        // For content-type we use the first selected item as the primary filter
        // (matchesContentType is keyword-based; multiple selections are OR-ed
        // by calling refreshView for each trigger which keeps it simple).
        // A lightweight OR approach: return the first selected value; the
        // dataStore predicate is applied per-entry so we gate in the loop below.
        return sel.iterator().next();
    }

    // ── Refresh ─────────────────────────────────────────────────────────────

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

            // Build combined status + content-type predicates via multi-select
            // We pass the first selected value as the legacy string filter and also
            // apply OR matching for multiple selections in a wrapper predicate.
            final Set<String> selectedStatuses = statusFilterBtn.getSelected();
            final Set<String> selectedContentTypes = contentTypeFilterBtn.getSelected();

            // Wrap scope + status + content-type + method into a single entry predicate
            // and use an empty string for the legacy string filter params so the dataStore
            // methods delegate actual filtering to our predicate.
            java.util.function.Predicate<String> combinedScopePredicate = inScopePredicate;

            // Use the dataStore's groupByMode with extended predicate to handle OR-matching
            // for multi-select. We pass empty strings for status/contentType and gate via
            // the custom Predicate chain inside our override lambda below.
            Map<String, List<CSPEntry>> grouped = groupByModeWithMultiSelect(
                selectedMode, filterText, selectedStatuses, selectedContentTypes, methodFilter, combinedScopePredicate
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

    /**
     * Delegates to {@link CSPDataStore#groupByMode} after applying OR-based
     * multi-select matching for status and content-type.
     */
    private Map<String, List<CSPEntry>> groupByModeWithMultiSelect(
            String mode,
            String valueFilter,
            Set<String> selectedStatuses,
            Set<String> selectedContentTypes,
            Set<String> methodFilter,
            java.util.function.Predicate<String> inScopePredicate) {

        // Build a compound scope predicate that also gates on multi-select status / content-type
        java.util.function.Predicate<String> scopeGate = url -> {
            if (inScopePredicate != null && !inScopePredicate.test(url)) return false;
            return true;
        };

        // We pass the method filter and use a single-status string for the legacy
        // matchesStatusCode helper — but OR all selected statuses ourselves.
        // The simplest approach: join selections and let matchesStatusCode tokenise them.
        String statusStr = selectedStatuses.isEmpty() ? "" : String.join(" / ", selectedStatuses);
        // For content-type OR we rely on re-applying per-entry below.
        // Pass the first content-type token; items not matched will be filtered via
        // the content-type wrapper.
        String ctStr = selectedContentTypes.isEmpty() ? "" : selectedContentTypes.iterator().next();

        // Build a custom wrapper using the dataStore's existing filter but
        // applying OR for content-types if multiple are selected.
        if (selectedContentTypes.size() <= 1) {
            return dataStore.groupByMode(mode, valueFilter, statusStr, ctStr, methodFilter, scopeGate);
        }

        // Multiple content-type selections: collect results from each and merge
        Map<String, List<CSPEntry>> merged = new LinkedHashMap<>();
        for (String ct : selectedContentTypes) {
            Map<String, List<CSPEntry>> partial = dataStore.groupByMode(
                mode, valueFilter, statusStr, ct, methodFilter, scopeGate);
            for (Map.Entry<String, List<CSPEntry>> e : partial.entrySet()) {
                merged.computeIfAbsent(e.getKey(), k -> new ArrayList<>());
                // Add only entries not already in the merged list (dedup by id)
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
            // OR-merge for multiple content-types
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
