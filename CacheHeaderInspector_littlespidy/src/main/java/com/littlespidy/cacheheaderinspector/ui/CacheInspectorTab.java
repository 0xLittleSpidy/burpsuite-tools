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

    // Summary Table Components
    private final CacheSummaryTableModel summaryTableModel = new CacheSummaryTableModel();
    private final JTable summaryTable = new JTable(summaryTableModel);

    // URL Entries Table Components
    private final CacheEntryTableModel entryTableModel = new CacheEntryTableModel();
    private final JTable entryTable = new JTable(entryTableModel);

    // Montoya Request / Response Editors
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    // Filter Controls
    private final JComboBox<String> headerComboBox = new JComboBox<>(TRACKED_HEADERS);
    private final JTextField valueFilterField = new JTextField(18);
    private final JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-Scope Only", false);
    private final JLabel statsLabel = new JLabel("Total Responses: 0 | Unique Directives: 0 | Displayed URLs: 0");
    private final JLabel currentHeaderLabel = new JLabel("Directives for: Cache-Control");

    // UI Debounce Timer
    private final javax.swing.Timer refreshTimer;
    private volatile boolean needsRefresh = false;

    // Currently selected directive filter from the summary table
    private String selectedDirectiveValue = null;

    public CacheInspectorTab(MontoyaApi api, CacheDataStore dataStore) {
        this.api = api;
        this.dataStore = dataStore;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout());

        // Setup debounced UI refresh timer (400ms)
        this.refreshTimer = new javax.swing.Timer(400, e -> {
            if (needsRefresh) {
                needsRefresh = false;
                refreshView();
            }
        });
        this.refreshTimer.setRepeats(true);
        this.refreshTimer.start();

        // Listen for new data arrivals
        dataStore.addListener(() -> {
            needsRefresh = true;
        });

        // Tab 1: Welcome & Guide
        rootTabbedPane.addTab("Welcome & Guide", createWelcomePanel());

        // Tab 2: Cache Header Inspector
        rootTabbedPane.addTab("Cache Header Inspector", createInspectorPanel());

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

        JLabel titleLabel = new JLabel("Cache Header Inspector");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setText(
            "Cache Header Inspector provides an interactive, real-time overview of all caching behavior "
                + "and HTTP response headers across your target applications.\n\n"
                + "Easily identify endpoints with missing cache controls, sensitive data cached in CDN/proxies, "
                + "Web Cache Deception risks, or potential Web Cache Poisoning surfaces."
        );

        JPanel headerPanel = new JPanel(new BorderLayout(5, 10));
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);

        // Feature cards
        JPanel cardsPanel = new JPanel(new GridLayout(0, 2, 20, 20));
        cardsPanel.add(createCard(
            "1. Real-Time Passive Inspection",
            "Automatically intercepts all HTTP traffic passing through Burp (Proxy, Repeater, Scanner) "
                + "and indexes 12 key caching and CDN headers."
        ));
        cardsPanel.add(createCard(
            "2. Directive Aggregation & URL Grouping",
            "Groups all discovered URLs by unique directive values (e.g. max-age=0, public, no-store). "
                + "Clicking any directive immediately displays all associated URLs."
        ));
        cardsPanel.add(createCard(
            "3. Multi-Header Filtering & Search",
            "Switch between Cache-Control, Pragma, Expires, ETag, Age, Vary, X-Cache, CF-Cache-Status, "
                + "and CDN headers with full-text filtering and quick preset chips."
        ));
        cardsPanel.add(createCard(
            "4. Built-in Master-Detail Viewer",
            "Select any URL to immediately inspect the raw HTTP request and response in Burp's native "
                + "Pretty/Raw/Hex editors without leaving the tab."
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

        // ── Top Control & Filter Toolbar ──
        JPanel topContainer = new JPanel(new BorderLayout(5, 5));
        topContainer.add(createMainToolbar(), BorderLayout.NORTH);
        topContainer.add(createQuickFilterToolbar(), BorderLayout.SOUTH);
        panel.add(topContainer, BorderLayout.NORTH);

        // ── Center Workspaces ──
        // Top: Summary Table
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
                    int modelRow = summaryTable.convertRowIndexToModel(row);
                    selectedDirectiveValue = summaryTableModel.getDirectiveValueAt(modelRow);
                    updateEntryTableForSelection();
                }
            }
        });
        setupTableKeyboardCopy(summaryTable);
        summaryPanel.add(new JScrollPane(summaryTable), BorderLayout.CENTER);

        // Bottom: URLs Table + Montoya Editors (Master-Detail)
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
                    int modelRow = entryTable.convertRowIndexToModel(row);
                    CacheEntry entry = entryTableModel.getEntryAt(modelRow);
                    if (entry != null) {
                        if (entry.request() != null) requestEditor.setRequest(entry.request());
                        if (entry.response() != null) responseEditor.setResponse(entry.response());
                    }
                }
            }
        });
        setupTableKeyboardCopy(entryTable);

        // Editors TabbedPane
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

        // Main Split Pane: Summary (Top) vs Associated URLs & Editors (Bottom)
        JSplitPane mainSplit = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            summaryPanel,
            detailsPanel
        );
        mainSplit.setResizeWeight(0.35);
        panel.add(mainSplit, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createMainToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton loadHistoryBtn = new JButton("Load Proxy History");
        loadHistoryBtn.setToolTipText("Import all captured requests and responses from Burp Proxy history");
        loadHistoryBtn.addActionListener(e -> loadProxyHistory());

        JLabel headerLbl = new JLabel("Inspect Header:");
        headerLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));

        headerComboBox.addActionListener(e -> {
            selectedDirectiveValue = null;
            refreshView();
        });

        JLabel filterLbl = new JLabel("Filter Value:");
        valueFilterField.setToolTipText("Filter directive values (e.g. no-store, max-age, public, private)");
        valueFilterField.addActionListener(e -> refreshView());

        JButton applyFilterBtn = new JButton("Apply");
        applyFilterBtn.addActionListener(e -> refreshView());

        JButton clearFilterBtn = new JButton("Reset Filter");
        clearFilterBtn.addActionListener(e -> {
            valueFilterField.setText("");
            selectedDirectiveValue = null;
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
                "Are you sure you want to clear all captured cache entries?",
                "Clear Data",
                JOptionPane.YES_NO_OPTION
            );
            if (confirm == JOptionPane.YES_OPTION) {
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
        JLabel quickLbl = new JLabel("Quick Filters:");
        quickLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        chipsPanel.add(quickLbl);

        String[] quickPresets = {
            "no-store", "no-cache", "public", "private", "max-age=0",
            "must-revalidate", "stale-while-revalidate", "HIT", "MISS", "(not set)"
        };

        for (String preset : quickPresets) {
            JButton chip = new JButton(preset);
            chip.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            chip.setMargin(new Insets(1, 6, 1, 6));
            chip.addActionListener(e -> {
                if (preset.equals("HIT") || preset.equals("MISS")) {
                    headerComboBox.setSelectedItem("X-Cache");
                } else if (preset.equals("(not set)")) {
                    // Filter specifically for not set
                } else {
                    headerComboBox.setSelectedItem("Cache-Control");
                }
                valueFilterField.setText(preset);
                selectedDirectiveValue = null;
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

    private void setupEntryTableRendering() {
        entryTable.getColumnModel().getColumn(0).setMaxWidth(50); // #
        entryTable.getColumnModel().getColumn(1).setMaxWidth(65); // Status

        entryTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
            ) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                int modelRow = table.convertRowIndexToModel(row);
                CacheEntry entry = entryTableModel.getEntryAt(modelRow);

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
        // Header
        for (int col = 0; col < table.getColumnCount(); col++) {
            sb.append(table.getColumnName(col)).append(col == table.getColumnCount() - 1 ? "\n" : "\t");
        }
        // Rows
        for (int row : selectedRows) {
            for (int col = 0; col < table.getColumnCount(); col++) {
                Object val = table.getValueAt(row, col);
                sb.append(val != null ? val.toString() : "").append(col == table.getColumnCount() - 1 ? "\n" : "\t");
            }
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
    }

    private void exportCurrentEntriesToTsv() {
        List<CacheEntry> entries = entryTableModel.getAllEntries();
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
        SwingWorker<List<CacheEntry>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<CacheEntry> doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                List<CacheEntry> list = new ArrayList<>();
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

                    CacheEntry entry = new CacheEntry(
                        dataStore.nextId(),
                        url,
                        host,
                        path,
                        resp.statusCode(),
                        resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "",
                        resp.headerValue("Cache-Control") != null ? resp.headerValue("Cache-Control") : "",
                        resp.headerValue("Pragma") != null ? resp.headerValue("Pragma") : "",
                        resp.headerValue("Expires") != null ? resp.headerValue("Expires") : "",
                        resp.headerValue("Age") != null ? resp.headerValue("Age") : "",
                        resp.headerValue("ETag") != null ? resp.headerValue("ETag") : "",
                        resp.headerValue("Last-Modified") != null ? resp.headerValue("Last-Modified") : "",
                        resp.headerValue("Vary") != null ? resp.headerValue("Vary") : "",
                        resp.headerValue("X-Cache") != null ? resp.headerValue("X-Cache") : "",
                        resp.headerValue("X-Cache-Hits") != null ? resp.headerValue("X-Cache-Hits") : "",
                        resp.headerValue("CDN-Cache-Control") != null ? resp.headerValue("CDN-Cache-Control") : "",
                        resp.headerValue("Surrogate-Control") != null ? resp.headerValue("Surrogate-Control") : "",
                        resp.headerValue("CF-Cache-Status") != null ? resp.headerValue("CF-Cache-Status") : "",
                        item.request(),
                        resp,
                        ZonedDateTime.now()
                    );
                    list.add(entry);
                }
                return list;
            }

            @Override
            protected void done() {
                try {
                    List<CacheEntry> result = get();
                    dataStore.addEntries(result);
                    refreshView();
                    JOptionPane.showMessageDialog(
                        CacheInspectorTab.this,
                        "Successfully imported " + result.size() + " responses from Proxy history.",
                        "Import Complete",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    api.logging().logToError("Error loading proxy history: " + ex.getMessage());
                }
            }
        };

        worker.execute();
    }

    public synchronized void refreshView() {
        SwingUtilities.invokeLater(() -> {
            String selectedHeader = (String) headerComboBox.getSelectedItem();
            if (selectedHeader == null) selectedHeader = "Cache-Control";

            String filterText = valueFilterField.getText().trim();
            boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

            // 1. Get raw grouped data
            Map<String, List<CacheEntry>> grouped = dataStore.groupByDirectiveFiltered(selectedHeader, filterText);

            // Filter in-scope if checked
            if (inScopeOnly) {
                Map<String, List<CacheEntry>> scopeFiltered = new LinkedHashMap<>();
                for (Map.Entry<String, List<CacheEntry>> entry : grouped.entrySet()) {
                    List<CacheEntry> inScopeList = new ArrayList<>();
                    for (CacheEntry ce : entry.getValue()) {
                        if (api.scope().isInScope(ce.url())) {
                            inScopeList.add(ce);
                        }
                    }
                    if (!inScopeList.isEmpty()) {
                        scopeFiltered.put(entry.getKey(), inScopeList);
                    }
                }
                grouped = scopeFiltered;
            }

            summaryTableModel.updateData(grouped);

            // 2. Update Entry table
            updateEntryTableForSelection();

            // 3. Update stats
            int totalCaptures = dataStore.size();
            int uniqueDirectives = summaryTableModel.getRowCount();
            int displayedUrls = entryTableModel.getRowCount();
            statsLabel.setText(
                "Total Responses: " + totalCaptures +
                " | Unique Directives: " + uniqueDirectives +
                " | Displayed URLs: " + displayedUrls
            );
        });
    }

    private void updateEntryTableForSelection() {
        String selectedHeader = (String) headerComboBox.getSelectedItem();
        if (selectedHeader == null) selectedHeader = "Cache-Control";

        boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();
        List<CacheEntry> entriesToShow = new ArrayList<>();

        if (selectedDirectiveValue != null) {
            // Find entries matching the selected directive value
            for (CacheEntry entry : dataStore.getEntries()) {
                if (inScopeOnly && !api.scope().isInScope(entry.url())) continue;

                String val = entry.getHeaderValue(selectedHeader);
                if (val == null || val.trim().isEmpty()) val = "(not set)";

                if (val.equals(selectedDirectiveValue)) {
                    entriesToShow.add(entry);
                }
            }
        } else {
            // Show all entries matching current header and search text filter
            String filterText = valueFilterField.getText().trim();
            for (CacheEntry entry : dataStore.getEntries()) {
                if (inScopeOnly && !api.scope().isInScope(entry.url())) continue;

                String val = entry.getHeaderValue(selectedHeader);
                if (val == null || val.trim().isEmpty()) val = "(not set)";

                if (filterText.isEmpty() || val.toLowerCase().contains(filterText.toLowerCase())) {
                    entriesToShow.add(entry);
                }
            }
        }

        entryTableModel.updateData(entriesToShow);
    }
}
