// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.ui;

import com.littlespidy.cacheheaderinspector.model.CacheDataStore;
import com.littlespidy.cacheheaderinspector.model.CacheEntry;
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
 * Top-level suite tab containing Welcome & Guide and the interactive Cache Header Inspector workspace.
 * Provides multi-select filtering by HTTP Method, Status Code, and Content-Type.
 *
 * @author littlespidy
 */
public class CacheInspectorTab extends JPanel {

    public static final String[] TRACKED_HEADERS = {
        "Cache-Control",
        "Pragma",
        "Expires",
        "Age",
        "ETag",
        "Last-Modified",
        "Vary",
        "X-Cache",
        "X-Cache-Hits",
        "CDN-Cache-Control",
        "Surrogate-Control",
        "CF-Cache-Status"
    };

    private final MontoyaApi api;
    private final CacheDataStore dataStore;

    private final JTabbedPane rootTabbedPane = new JTabbedPane();

    // Summary Table
    private final CacheSummaryTableModel summaryTableModel = new CacheSummaryTableModel();
    private final JTable summaryTable = new JTable(summaryTableModel);

    // URL Entries Table
    private final CacheEntryTableModel entryTableModel = new CacheEntryTableModel();
    private final JTable entryTable = new JTable(entryTableModel);

    // Montoya Request / Response Editors
    private final HttpRequestEditor  requestEditor;
    private final HttpResponseEditor responseEditor;

    // ─── Multi-Select Filter Buttons ──────────────────────────────────────────
    private final MultiSelectFilterButton statusFilterBtn = new MultiSelectFilterButton(
        "Status",
        List.of("All Status Codes","2xx Success","200 OK","3xx Redirection",
                "301 / 302 Redirect","304 Not Modified","4xx Client Error",
                "401 Unauthorized","403 Forbidden","404 Not Found",
                "5xx Server Error","500 Internal Error"),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton contentTypeFilterBtn = new MultiSelectFilterButton(
        "Content-Type",
        List.of("All Content-Types","HTML (text/html)","JSON (application/json)",
                "JavaScript (text/javascript)","CSS (text/css)","XML (application/xml)",
                "Plain Text (text/plain)","Images (image/*)","PDF / Documents (application/pdf)"),
        sel -> refreshView()
    );

    private final MultiSelectFilterButton methodFilterBtn = new MultiSelectFilterButton(
        "Method",
        List.of("All Methods","GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"),
        sel -> refreshView()
    );
    // ─────────────────────────────────────────────────────────────────────────

    // Other filter controls
    private final JComboBox<String> headerComboBox    = new JComboBox<>(TRACKED_HEADERS);
    private final JTextField valueFilterField         = new JTextField(14);
    private final JCheckBox inScopeOnlyCheckBox       = new JCheckBox("In-Scope Only", false);
    private final JLabel statsLabel = new JLabel("Total Unique URLs: 0 | Unique Directives: 0 | Displayed URLs: 0");

    // UI Debounce Timer
    private final javax.swing.Timer refreshTimer;
    private volatile boolean needsRefresh = false;

    // Currently selected directive filter from the summary table
    private String selectedDirectiveValue = null;

    public CacheInspectorTab(MontoyaApi api, CacheDataStore dataStore) {
        this.api       = api;
        this.dataStore = dataStore;
        this.requestEditor  = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout());

        this.refreshTimer = new javax.swing.Timer(400, e -> {
            if (needsRefresh) { needsRefresh = false; refreshView(); }
        });
        this.refreshTimer.setRepeats(true);
        this.refreshTimer.start();

        dataStore.addListener(() -> needsRefresh = true);

        rootTabbedPane.addTab("Welcome & Guide",       createWelcomePanel());
        rootTabbedPane.addTab("Cache Header Inspector", createInspectorPanel());
        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void cleanup() {
        if (refreshTimer != null && refreshTimer.isRunning()) refreshTimer.stop();
    }

    // ── Welcome panel ─────────────────────────────────────────────────────────

    private JComponent createWelcomePanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        JLabel titleLabel = new JLabel("Cache Header Inspector");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea(
            "Cache Header Inspector provides an interactive, on-demand overview of HTTP caching behavior "
            + "and response headers across your target applications.\n\n"
            + "Easily identify endpoints with missing cache controls, sensitive data cached in CDN/proxies, "
            + "Web Cache Deception risks, or potential Web Cache Poisoning surfaces."
        );
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);

        JPanel headerPanel = new JPanel(new BorderLayout(5, 10));
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descArea,   BorderLayout.CENTER);

        JPanel cardsPanel = new JPanel(new GridLayout(0, 2, 20, 20));
        cardsPanel.add(createCard("1. On-Demand Target Ingestion & Deduplication",
            "Click 'Load Proxy History' to instantly ingest and deduplicate past traffic "
            + "from Burp Proxy history. Deduplication is by Method + URL."));
        cardsPanel.add(createCard("2. Directive Aggregation & URL Grouping",
            "Groups all unique endpoints by directive values (e.g. max-age=0, public, no-store). "
            + "Clicking any directive row instantly filters all matching URLs."));
        cardsPanel.add(createCard("3. Multi-Select Triage Filters",
            "Filter simultaneously by HTTP Method (GET/POST/…), Status Code (200, 302, 4xx), "
            + "and Content-Type (html, json). Select multiple values at once."));
        cardsPanel.add(createCard("4. Built-in Master-Detail Viewer",
            "Select any URL to inspect the raw HTTP request and response in Burp's native "
            + "Pretty/Raw/Hex editors without leaving the tab."));

        panel.add(headerPanel, BorderLayout.NORTH);
        panel.add(cardsPanel,  BorderLayout.CENTER);
        return new JScrollPane(panel);
    }

    private JPanel createCard(String title, String description) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(200, 200, 200), 1, true),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));
        JLabel lbl = new JLabel(title);
        lbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 15));
        JTextArea ta = new JTextArea(description);
        ta.setEditable(false); ta.setOpaque(false);
        ta.setLineWrap(true);  ta.setWrapStyleWord(true);
        ta.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        card.add(lbl, BorderLayout.NORTH);
        card.add(ta,  BorderLayout.CENTER);
        return card;
    }

    // ── Inspector panel ───────────────────────────────────────────────────────

    private JPanel createInspectorPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topContainer = new JPanel(new BorderLayout(5, 5));
        topContainer.add(createMainToolbar(),        BorderLayout.NORTH);
        topContainer.add(createQuickFilterToolbar(), BorderLayout.SOUTH);
        panel.add(topContainer, BorderLayout.NORTH);

        // Summary table
        JPanel summaryPanel = new JPanel(new BorderLayout(5, 5));
        summaryPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Cache Directive Values Overview",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));
        summaryTable.setRowSorter(new TableRowSorter<>(summaryTableModel));
        summaryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        summaryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = summaryTable.getSelectedRow();
                if (row >= 0) {
                    int mr = summaryTable.convertRowIndexToModel(row);
                    selectedDirectiveValue = summaryTableModel.getDirectiveValueAt(mr);
                    updateEntryTableForSelection();
                }
            }
        });
        setupTableKeyboardCopy(summaryTable);
        summaryPanel.add(new JScrollPane(summaryTable), BorderLayout.CENTER);

        // Endpoint detail table + editors
        JPanel detailsPanel = new JPanel(new BorderLayout(5, 5));
        detailsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Associated URLs",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));
        entryTable.setRowSorter(new TableRowSorter<>(entryTableModel));
        entryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupEntryTableRendering();
        entryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = entryTable.getSelectedRow();
                if (row >= 0) {
                    int mr = entryTable.convertRowIndexToModel(row);
                    CacheEntry entry = entryTableModel.getEntryAt(mr);
                    if (entry != null) {
                        if (entry.request()  != null) requestEditor.setRequest(entry.request());
                        if (entry.response() != null) responseEditor.setResponse(entry.response());
                    }
                }
            }
        });
        setupTableKeyboardCopy(entryTable);

        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Request",  requestEditor.uiComponent());
        editorTabs.addTab("Response", responseEditor.uiComponent());

        JSplitPane masterDetailSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(entryTable), editorTabs);
        masterDetailSplit.setResizeWeight(0.55);
        detailsPanel.add(masterDetailSplit, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, summaryPanel, detailsPanel);
        mainSplit.setResizeWeight(0.35);
        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }

    // ── Toolbars ──────────────────────────────────────────────────────────────

    private JPanel createMainToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton loadHistoryBtn = new JButton("Load Proxy History");
        loadHistoryBtn.setToolTipText("Import and deduplicate requests from Burp Proxy history");
        loadHistoryBtn.addActionListener(e -> loadProxyHistory());

        JLabel headerLbl = new JLabel("Inspect Header:");
        headerLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        headerComboBox.addActionListener(e -> { selectedDirectiveValue = null; refreshView(); });

        JLabel filterLbl = new JLabel("Directive:");
        valueFilterField.setToolTipText("Filter directive values (e.g. no-store, max-age, public, private)");
        valueFilterField.addActionListener(e -> refreshView());

        // Multi-select filter buttons
        methodFilterBtn.setToolTipText("Multi-select HTTP methods to filter by");
        statusFilterBtn.setToolTipText("Multi-select HTTP status codes to filter by");
        contentTypeFilterBtn.setToolTipText("Multi-select Content-Types to filter by");

        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> refreshView());

        JButton resetBtn = new JButton("Reset Filters");
        resetBtn.addActionListener(e -> {
            valueFilterField.setText("");
            statusFilterBtn.clearSelection();
            contentTypeFilterBtn.clearSelection();
            methodFilterBtn.clearSelection();
            selectedDirectiveValue = null;
            refreshView();
        });

        inScopeOnlyCheckBox.addActionListener(e -> refreshView());

        JButton exportTsvBtn = new JButton("Export TSV");
        exportTsvBtn.setToolTipText("Export currently displayed URL results to clipboard as TSV");
        exportTsvBtn.addActionListener(e -> exportCurrentEntriesToTsv());

        JButton clearDataBtn = new JButton("Clear All Data");
        clearDataBtn.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to clear all captured cache entries?",
                "Clear Data", JOptionPane.YES_NO_OPTION);
            if (ok == JOptionPane.YES_OPTION) {
                dataStore.clear();
                selectedDirectiveValue = null;
                refreshView();
            }
        });

        toolbar.add(loadHistoryBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(headerLbl);
        toolbar.add(headerComboBox);
        toolbar.add(filterLbl);
        toolbar.add(valueFilterField);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(methodFilterBtn);
        toolbar.add(statusFilterBtn);
        toolbar.add(contentTypeFilterBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(applyBtn);
        toolbar.add(resetBtn);
        toolbar.add(inScopeOnlyCheckBox);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(exportTsvBtn);
        toolbar.add(clearDataBtn);
        return toolbar;
    }

    private JPanel createQuickFilterToolbar() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JPanel chipsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JLabel quickLbl = new JLabel("Quick Filters:");
        quickLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        chipsPanel.add(quickLbl);

        addChip(chipsPanel, "no-store",             "Cache-Control", "no-store");
        addChip(chipsPanel, "no-cache",             "Cache-Control", "no-cache");
        addChip(chipsPanel, "public",               "Cache-Control", "public");
        addChip(chipsPanel, "private",              "Cache-Control", "private");
        addChip(chipsPanel, "max-age=0",            "Cache-Control", "max-age=0");
        addChip(chipsPanel, "must-revalidate",      "Cache-Control", "must-revalidate");
        addChip(chipsPanel, "stale-while-revalidate","Cache-Control","stale-while-revalidate");
        addChip(chipsPanel, "HIT",                  "X-Cache",       "HIT");
        addChip(chipsPanel, "MISS",                 "X-Cache",       "MISS");
        addChip(chipsPanel, "(not set)",             null,            "(not set)");

        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 2));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        statsPanel.add(statsLabel);

        panel.add(chipsPanel, BorderLayout.WEST);
        panel.add(statsPanel, BorderLayout.EAST);
        return panel;
    }

    private void addChip(JPanel parent, String label, String header, String keyword) {
        JButton chip = new JButton(label);
        chip.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        chip.setMargin(new Insets(1, 6, 1, 6));
        chip.addActionListener(e -> {
            if (header != null) headerComboBox.setSelectedItem(header);
            valueFilterField.setText(keyword);
            selectedDirectiveValue = null;
            refreshView();
        });
        parent.add(chip);
    }

    // ── Table rendering ───────────────────────────────────────────────────────

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
                    CacheEntry entry = entryTableModel.getEntryAt(mr);
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
        List<CacheEntry> entries = entryTableModel.getAllEntries();
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

    // ── Proxy history loading ─────────────────────────────────────────────────

    private void loadProxyHistory() {
        SwingWorker<List<CacheEntry>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<CacheEntry> doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                Map<String, CacheEntry> unique = new LinkedHashMap<>();
                boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

                for (ProxyHttpRequestResponse item : history) {
                    if (!item.hasResponse()) continue;
                    String url = item.request().url();
                    if (inScopeOnly && !api.scope().isInScope(url)) continue;

                    var resp   = item.response();
                    String host   = item.request().httpService() != null ? item.request().httpService().host() : "";
                    String path   = item.request().path() != null ? item.request().path() : "/";
                    String method = item.request().method() != null ? item.request().method().toUpperCase() : "GET";
                    String key    = method + " " + url;

                    CacheEntry entry = new CacheEntry(
                        dataStore.nextId(), url, host, path, method,
                        resp.statusCode(),
                        resp.headerValue("Content-Type")        != null ? resp.headerValue("Content-Type")        : "",
                        resp.headerValue("Cache-Control")       != null ? resp.headerValue("Cache-Control")       : "",
                        resp.headerValue("Pragma")              != null ? resp.headerValue("Pragma")              : "",
                        resp.headerValue("Expires")             != null ? resp.headerValue("Expires")             : "",
                        resp.headerValue("Age")                 != null ? resp.headerValue("Age")                 : "",
                        resp.headerValue("ETag")                != null ? resp.headerValue("ETag")                : "",
                        resp.headerValue("Last-Modified")       != null ? resp.headerValue("Last-Modified")       : "",
                        resp.headerValue("Vary")                != null ? resp.headerValue("Vary")                : "",
                        resp.headerValue("X-Cache")             != null ? resp.headerValue("X-Cache")             : "",
                        resp.headerValue("X-Cache-Hits")        != null ? resp.headerValue("X-Cache-Hits")        : "",
                        resp.headerValue("CDN-Cache-Control")   != null ? resp.headerValue("CDN-Cache-Control")   : "",
                        resp.headerValue("Surrogate-Control")   != null ? resp.headerValue("Surrogate-Control")   : "",
                        resp.headerValue("CF-Cache-Status")     != null ? resp.headerValue("CF-Cache-Status")     : "",
                        item.request(), resp, ZonedDateTime.now()
                    );
                    unique.put(key, entry);
                }
                return new ArrayList<>(unique.values());
            }

            @Override
            protected void done() {
                try {
                    List<CacheEntry> result = get();
                    dataStore.addEntries(result);
                    refreshView();
                    JOptionPane.showMessageDialog(CacheInspectorTab.this,
                        "Successfully imported " + result.size() + " unique URLs from Proxy history.",
                        "Import Complete", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    api.logging().logToError("CacheInspector: error loading proxy history: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    // ── Refresh logic ─────────────────────────────────────────────────────────

    public synchronized void refreshView() {
        SwingUtilities.invokeLater(() -> {
            String selectedHeader = (String) headerComboBox.getSelectedItem();
            if (selectedHeader == null) selectedHeader = "Cache-Control";

            String filterText  = valueFilterField.getText().trim();
            boolean inScope    = inScopeOnlyCheckBox.isSelected();

            Set<String> methodSel = methodFilterBtn.getSelected();
            Set<String> statusSel = statusFilterBtn.getSelected();
            Set<String> ctSel     = contentTypeFilterBtn.getSelected();

            java.util.function.Predicate<String> scopePred = inScope
                ? url -> api.scope().isInScope(url) : null;

            String statusStr = statusSel.isEmpty() ? "" : String.join(" / ", statusSel);

            Map<String, List<CacheEntry>> grouped =
                groupWithMultiSelectCT(selectedHeader, filterText, statusStr, ctSel, methodSel, scopePred);

            summaryTableModel.updateData(grouped);
            updateEntryTableForSelection();

            statsLabel.setText(
                "Total Unique URLs: " + dataStore.size()
                + " | Unique Directives: " + summaryTableModel.getRowCount()
                + " | Displayed URLs: " + entryTableModel.getRowCount()
            );
        });
    }

    private void updateEntryTableForSelection() {
        String selectedHeader = (String) headerComboBox.getSelectedItem();
        if (selectedHeader == null) selectedHeader = "Cache-Control";

        String filterText  = valueFilterField.getText().trim();
        boolean inScope    = inScopeOnlyCheckBox.isSelected();

        Set<String> methodSel = methodFilterBtn.getSelected();
        Set<String> statusSel = statusFilterBtn.getSelected();
        Set<String> ctSel     = contentTypeFilterBtn.getSelected();

        java.util.function.Predicate<String> scopePred = inScope
            ? url -> api.scope().isInScope(url) : null;

        String statusStr = statusSel.isEmpty() ? "" : String.join(" / ", statusSel);

        List<CacheEntry> entries;
        if (ctSel.size() <= 1) {
            String ct = ctSel.isEmpty() ? "" : ctSel.iterator().next();
            entries = dataStore.getFilteredEntries(selectedHeader, selectedDirectiveValue,
                filterText, statusStr, ct, methodSel, scopePred);
        } else {
            Map<Integer, CacheEntry> merged = new LinkedHashMap<>();
            for (String ct : ctSel) {
                dataStore.getFilteredEntries(selectedHeader, selectedDirectiveValue,
                    filterText, statusStr, ct, methodSel, scopePred)
                    .forEach(e -> merged.putIfAbsent(e.id(), e));
            }
            entries = new ArrayList<>(merged.values());
        }
        entryTableModel.updateData(entries);
    }

    /** OR-merges multiple content-type selections when building the summary table. */
    private Map<String, List<CacheEntry>> groupWithMultiSelectCT(
            String header, String kw, String statusStr,
            Set<String> ctSel, Set<String> methodSel,
            java.util.function.Predicate<String> scopePred) {

        if (ctSel.size() <= 1) {
            String ct = ctSel.isEmpty() ? "" : ctSel.iterator().next();
            return dataStore.groupByDirectiveFiltered(header, kw, statusStr, ct, methodSel, scopePred);
        }
        Map<String, List<CacheEntry>> merged = new LinkedHashMap<>();
        for (String ct : ctSel) {
            dataStore.groupByDirectiveFiltered(header, kw, statusStr, ct, methodSel, scopePred)
                .forEach((key, list) -> {
                    merged.computeIfAbsent(key, k -> new ArrayList<>());
                    Set<Integer> seen = new HashSet<>();
                    merged.get(key).forEach(e -> seen.add(e.id()));
                    list.stream().filter(e -> seen.add(e.id())).forEach(merged.get(key)::add);
                });
        }
        return merged;
    }
}
