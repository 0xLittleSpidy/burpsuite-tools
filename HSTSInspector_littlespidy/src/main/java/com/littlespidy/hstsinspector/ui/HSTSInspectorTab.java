// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.ui;

import com.littlespidy.hstsinspector.model.HSTSDataStore;
import com.littlespidy.hstsinspector.model.HSTSEntry;
import com.littlespidy.hstsinspector.model.HSTSParser;
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
 * Top-level UI tab for HSTS Inspector — provides grouped HSTS pattern overview,
 * per-endpoint detail table, multi-select filters (Method / Status / Content-Type),
 * and built-in master-detail HTTP request/response editors.
 *
 * @author littlespidy
 */
public class HSTSInspectorTab extends JPanel {

    // ── Inspect modes ─────────────────────────────────────────────────────────
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

    private final JTabbedPane rootTabbedPane = new JTabbedPane();

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

    // ── Other filter controls ─────────────────────────────────────────────────
    private final JComboBox<String> inspectModeComboBox = new JComboBox<>(INSPECT_MODES);
    private final JTextField valueFilterField = new JTextField(14);
    private final JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-Scope Only", false);
    private final JLabel statsLabel = new JLabel("Total Unique URLs: 0 | Patterns: 0 | Displayed: 0");

    // Debounce timer
    private final javax.swing.Timer refreshTimer;
    private volatile boolean needsRefresh = false;

    // Summary selection
    private String selectedSummaryValue = null;

    // ── Constructor ───────────────────────────────────────────────────────────

    public HSTSInspectorTab(MontoyaApi api, HSTSDataStore dataStore) {
        this.api       = api;
        this.dataStore = dataStore;
        this.requestEditor  = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout());

        this.refreshTimer = new javax.swing.Timer(350, e -> {
            if (needsRefresh) { needsRefresh = false; refreshView(); }
        });
        this.refreshTimer.setRepeats(true);
        this.refreshTimer.start();

        dataStore.addListener(() -> needsRefresh = true);

        rootTabbedPane.addTab("Welcome & Guide", createWelcomePanel());
        rootTabbedPane.addTab("HSTS Inspector",  createInspectorPanel());
        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void cleanup() {
        if (refreshTimer != null && refreshTimer.isRunning()) refreshTimer.stop();
    }

    // ── Welcome panel ─────────────────────────────────────────────────────────

    private JComponent createWelcomePanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        JLabel title = new JLabel("HTTP Strict Transport Security (HSTS) Inspector");
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea desc = new JTextArea(
            "HSTS Inspector audits the Strict-Transport-Security header across all target "
            + "endpoints loaded from Burp Proxy history.\n\n"
            + "Quickly identify:\n"
            + "  • Missing HSTS headers (HTTPS downgrade risk)\n"
            + "  • Short or zero max-age values\n"
            + "  • Missing includeSubDomains (subdomain cookie theft risk)\n"
            + "  • Missing preload directive (browser preload list eligibility)"
        );
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));

        JPanel header = new JPanel(new BorderLayout(5, 10));
        header.add(title, BorderLayout.NORTH);
        header.add(desc,  BorderLayout.CENTER);

        JPanel cards = new JPanel(new GridLayout(0, 2, 20, 20));
        cards.add(createCard("1. On-Demand Ingestion & Deduplication",
            "Load traffic from Burp Proxy history on-demand. Endpoints are deduplicated by "
            + "Method + URL — no noise."));
        cards.add(createCard("2. Assessment-First Grouping",
            "Default 'Assessment' mode groups endpoints by severity: CRITICAL, HIGH, MEDIUM, GOOD. "
            + "Rows are colour-coded for instant triage."));
        cards.add(createCard("3. Directive Drill-Down Modes",
            "Switch to max-age, includeSubDomains, or preload modes to see the distribution "
            + "of individual directive values across all endpoints."));
        cards.add(createCard("4. Multi-Select Filters + Master-Detail",
            "Filter by HTTP Method, Status Code, or Content-Type — multi-select supported. "
            + "Click any URL row to open the raw request/response in Burp's native editors."));

        panel.add(header, BorderLayout.NORTH);
        panel.add(cards,  BorderLayout.CENTER);
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
            BorderFactory.createEtchedBorder(), "HSTS Value Overview & Assessment",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));
        summaryTable.setRowSorter(new TableRowSorter<>(summaryTableModel));
        summaryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupSummaryRendering();
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

        // Endpoint detail + editors
        JPanel detailPanel = new JPanel(new BorderLayout(5, 5));
        detailPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Associated Endpoints",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));
        entryTable.setRowSorter(new TableRowSorter<>(entryTableModel));
        entryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupEntryRendering();
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
        editorTabs.addTab("Request",  requestEditor.uiComponent());
        editorTabs.addTab("Response", responseEditor.uiComponent());

        JSplitPane masterDetail = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(entryTable), editorTabs);
        masterDetail.setResizeWeight(0.55);
        detailPanel.add(masterDetail, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, summaryPanel, detailPanel);
        mainSplit.setResizeWeight(0.38);
        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }

    // ── Toolbars ──────────────────────────────────────────────────────────────

    private JPanel createMainToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton loadBtn = new JButton("Load Proxy History");
        loadBtn.setToolTipText("Import and deduplicate requests from Burp Proxy history");
        loadBtn.addActionListener(e -> loadProxyHistory());

        JLabel modeLbl = new JLabel("Inspect Mode:");
        modeLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        inspectModeComboBox.addActionListener(e -> { selectedSummaryValue = null; refreshView(); });

        JLabel kwLbl = new JLabel("Keyword:");
        valueFilterField.setToolTipText("Filter by any text (header value, assessment keyword, etc.)");
        valueFilterField.addActionListener(e -> refreshView());

        statusFilterBtn.setToolTipText("Multi-select HTTP status codes to filter by");
        contentTypeFilterBtn.setToolTipText("Multi-select Content-Types to filter by");
        methodFilterBtn.setToolTipText("Multi-select HTTP methods to filter by");

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

        JButton exportBtn = new JButton("Export TSV");
        exportBtn.setToolTipText("Copy displayed endpoints to clipboard as TSV");
        exportBtn.addActionListener(e -> exportTsv());

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

        bar.add(loadBtn);
        bar.add(new JSeparator(SwingConstants.VERTICAL));
        bar.add(modeLbl);
        bar.add(inspectModeComboBox);
        bar.add(kwLbl);
        bar.add(valueFilterField);
        bar.add(new JSeparator(SwingConstants.VERTICAL));
        bar.add(methodFilterBtn);
        bar.add(statusFilterBtn);
        bar.add(contentTypeFilterBtn);
        bar.add(new JSeparator(SwingConstants.VERTICAL));
        bar.add(applyBtn);
        bar.add(resetBtn);
        bar.add(inScopeOnlyCheckBox);
        bar.add(new JSeparator(SwingConstants.VERTICAL));
        bar.add(exportBtn);
        bar.add(clearBtn);
        return bar;
    }

    private JPanel createQuickFilterToolbar() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JPanel chips = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JLabel lbl = new JLabel("Quick Presets:");
        lbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        chips.add(lbl);

        addChip(chips, "(missing HSTS)",     () -> { setMode(HSTSDataStore.MODE_MISSING);     setKeyword(""); });
        addChip(chips, "max-age=0 (opt-out)",() -> { setMode(HSTSDataStore.MODE_MAX_AGE);    setKeyword("max-age=0"); });
        addChip(chips, "Short max-age",      () -> { setMode(HSTSDataStore.MODE_ASSESSMENT);  setKeyword("HIGH"); });
        addChip(chips, "No includeSubDomains",() ->{ setMode(HSTSDataStore.MODE_SUBDOMAINS);  setKeyword("absent"); });
        addChip(chips, "No preload",         () -> { setMode(HSTSDataStore.MODE_PRELOAD);     setKeyword("absent"); });
        addChip(chips, "Preload ready",      () -> { setMode(HSTSDataStore.MODE_PRELOAD);     setKeyword("present"); });
        addChip(chips, "CRITICAL",           () -> { setMode(HSTSDataStore.MODE_ASSESSMENT);  setKeyword("CRITICAL"); });
        addChip(chips, "GOOD",               () -> { setMode(HSTSDataStore.MODE_ASSESSMENT);  setKeyword("GOOD"); });

        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 2));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        statsPanel.add(statsLabel);

        panel.add(chips,     BorderLayout.WEST);
        panel.add(statsPanel, BorderLayout.EAST);
        return panel;
    }

    private void addChip(JPanel parent, String label, Runnable action) {
        JButton btn = new JButton(label);
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        btn.setMargin(new Insets(1, 6, 1, 6));
        btn.addActionListener(e -> { action.run(); selectedSummaryValue = null; refreshView(); });
        parent.add(btn);
    }

    private void setMode(String mode)    { inspectModeComboBox.setSelectedItem(mode); }
    private void setKeyword(String kw)   { valueFilterField.setText(kw); }

    // ── Table rendering ───────────────────────────────────────────────────────

    private void setupSummaryRendering() {
        summaryTable.getColumnModel().getColumn(1).setMaxWidth(65); // Count

        summaryTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    int mr = table.convertRowIndexToModel(row);
                    Object a = summaryTableModel.getValueAt(mr, 2);
                    String assessment = a != null ? a.toString().toUpperCase() : "";
                    if (assessment.startsWith("CRITICAL")) c.setBackground(new Color(255, 220, 220));
                    else if (assessment.startsWith("HIGH")) c.setBackground(new Color(255, 235, 210));
                    else if (assessment.startsWith("MEDIUM")) c.setBackground(new Color(255, 250, 210));
                    else if (assessment.startsWith("GOOD")) c.setBackground(new Color(230, 255, 230));
                    else c.setBackground(table.getBackground());
                }
                return c;
            }
        });
    }

    private void setupEntryRendering() {
        entryTable.getColumnModel().getColumn(0).setMaxWidth(50);  // #
        entryTable.getColumnModel().getColumn(1).setMaxWidth(65);  // Status
        entryTable.getColumnModel().getColumn(2).setMaxWidth(65);  // Method
        entryTable.getColumnModel().getColumn(7).setMaxWidth(130); // includeSubDomains
        entryTable.getColumnModel().getColumn(8).setMaxWidth(80);  // preload

        entryTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    int mr = table.convertRowIndexToModel(row);
                    HSTSEntry entry = entryTableModel.getEntryAt(mr);
                    if (entry != null) {
                        String a = entry.assessment().toUpperCase();
                        if (a.startsWith("CRITICAL"))   c.setBackground(new Color(255, 220, 220));
                        else if (a.startsWith("HIGH"))  c.setBackground(new Color(255, 235, 210));
                        else if (a.startsWith("MEDIUM"))c.setBackground(new Color(255, 250, 210));
                        else if (a.startsWith("GOOD"))  c.setBackground(new Color(230, 255, 230));
                        else                            c.setBackground(table.getBackground());
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

    // ── Proxy history loading ─────────────────────────────────────────────────

    private void loadProxyHistory() {
        SwingWorker<List<HSTSEntry>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<HSTSEntry> doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                Map<String, HSTSEntry> unique = new LinkedHashMap<>();
                boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

                for (ProxyHttpRequestResponse item : history) {
                    if (!item.hasResponse()) continue;
                    String url = item.request().url();
                    if (inScopeOnly && !api.scope().isInScope(url)) continue;

                    var resp   = item.response();
                    String host   = item.request().httpService() != null ? item.request().httpService().host() : "";
                    String path   = item.request().path() != null ? item.request().path() : "/";
                    String method = item.request().method() != null ? item.request().method().toUpperCase() : "GET";
                    String dedupeKey = method + " " + url;

                    String rawHsts = resp.headerValue("Strict-Transport-Security");
                    HSTSParser.ParsedHSTS parsed = HSTSParser.parse(rawHsts);

                    HSTSEntry entry = new HSTSEntry(
                        dataStore.nextId(),
                        url, host, path, method,
                        resp.statusCode(),
                        resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "",
                        rawHsts != null ? rawHsts : "",
                        parsed.maxAge(),
                        parsed.includeSubDomains(),
                        parsed.preload(),
                        item.request(), resp,
                        ZonedDateTime.now()
                    );
                    unique.put(dedupeKey, entry);
                }
                return new ArrayList<>(unique.values());
            }

            @Override
            protected void done() {
                try {
                    List<HSTSEntry> result = get();
                    dataStore.addEntries(result);
                    refreshView();
                    JOptionPane.showMessageDialog(HSTSInspectorTab.this,
                        "Imported " + result.size() + " unique endpoints from Proxy history.",
                        "Import Complete", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    api.logging().logToError("HSTSInspector: error loading proxy history: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    // ── TSV export ────────────────────────────────────────────────────────────

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

    // ── Refresh logic ─────────────────────────────────────────────────────────

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

    /** OR-merges multiple content-type selections when grouping the summary table. */
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
