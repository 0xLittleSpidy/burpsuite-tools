// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.gwtmap.engine.GWTScanEngine;
import com.littlespidy.gwtmap.model.GWTDataStore;
import com.littlespidy.gwtmap.model.GWTMethod;
import com.littlespidy.gwtmap.model.GWTModuleInfo;
import com.littlespidy.gwtmap.model.GWTService;
import com.littlespidy.gwtmap.model.GwtHttpHistoryEntry;
import com.littlespidy.gwtmap.persistence.GWTMapPersistenceManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.List;

/**
 * Main Suite Tab UI component for GWTMap.
 * Separates RPC Deserializer and RPC Fuzzer & Tester into distinct tabs,
 * combines analysis tools under 'GWT Analysis' with ordered subtabs,
 * provides accurate progress tracking, code search/highlighting, and cross-platform persistence.
 *
 * @author littlespidy
 */
public class GWTMapTab extends JPanel {

    private final MontoyaApi api;
    private final GWTDataStore dataStore;
    private final GWTScanEngine engine;
    private final GWTMapPersistenceManager persistenceManager;

    // Top Controls (Target Acquisition)
    private final JTextField urlField = new JTextField(28);
    private final JTextField baseField = new JTextField(18);
    private final JButton analyzeBtn = new JButton("Analyze Target");
    private final JButton openFileBtn = new JButton("Open Permutation Local File...");
    private final JComboBox<String> permutationCombo = new JComboBox<>();
    private final JButton headersBtn = new JButton("Headers & Cookies... (0)");
    private final JButton storageBtn = new JButton("Storage Folder...");
    private final JCheckBox passiveMonitorBox = new JCheckBox("Passive Monitor", true);
    private final JLabel statusLabel = new JLabel("Ready");
    private final JProgressBar progressBar = new JProgressBar();

    // Custom headers buffer
    private String customHeaders = "";

    // ── Main Top-Level Tabs ──────────────────────────────────────────────────
    private final JTabbedPane mainTabbedPane = new JTabbedPane();

    // ── GWT Analysis Sub-Tabs ────────────────────────────────────────────────
    private final JTabbedPane analysisTabbedPane = new JTabbedPane();

    // Subtab: Methods & Payloads
    private final GWTMethodTableModel methodTableModel = new GWTMethodTableModel();
    private final JTable methodTable = new JTable(methodTableModel);
    private final JTextField searchField = new JTextField(15);
    private final JComboBox<String> methodSelectCombo = new JComboBox<>();
    private boolean isSyncingMethodSelection = false;
    private MultiSelectFilterButton serviceFilterBtn;
    private final JLabel counterLabel = new JLabel("Showing 0/0 Services | 0/0 Methods");

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private final JTextArea rawRpcArea = new JTextArea();
    private final JTextArea evidenceArea = new JTextArea();

    // Subtab: HTTP History
    private final GwtHttpHistoryTableModel httpHistoryModel = new GwtHttpHistoryTableModel();
    private final JTable httpHistoryTable = new JTable(httpHistoryModel);
    private HttpRequestEditor historyRequestEditor;
    private HttpResponseEditor historyResponseEditor;

    // Subtab: Services & Policies
    private final GWTServiceTableModel serviceTableModel = new GWTServiceTableModel();
    private final JTable serviceTable = new JTable(serviceTableModel);

    // Subtab: Module Info
    private final JTextArea moduleInfoArea = new JTextArea();

    // Subtab: Deobfuscated Code
    private final JTextArea codeViewerArea = new JTextArea();
    private final JButton exportCodeBtn = new JButton("Save / Backup Code to Disk...");
    private final JTextField codeSearchField = new JTextField(18);
    private final JLabel codeMatchCountLabel = new JLabel("0 matches");
    private final JCheckBox codeMatchCaseBox = new JCheckBox("Match Case", false);
    private final List<int[]> codeMatchOffsets = new ArrayList<>();
    private int currentCodeMatchIdx = -1;
    private final DefaultHighlightPainter normalHighlightPainter = new DefaultHighlightPainter(new Color(255, 255, 140));
    private final DefaultHighlightPainter activeHighlightPainter = new DefaultHighlightPainter(new Color(255, 175, 75));

    // Independent Tool Tabs
    private final RpcDeserializerPanel deserializerPanel;
    private final RpcFuzzerPanel fuzzerPanel;

    // Debounce timer for search input (300ms)
    private final javax.swing.Timer filterDebounceTimer = new javax.swing.Timer(300, e -> refreshFilteredViews());
    {
        filterDebounceTimer.setRepeats(false);
    }

    public GWTMapTab(MontoyaApi api, GWTDataStore dataStore, GWTScanEngine engine) {
        this.api = api;
        this.dataStore = dataStore;
        this.engine = engine;
        this.persistenceManager = new GWTMapPersistenceManager(api);
        this.deserializerPanel = new RpcDeserializerPanel(api);
        this.fuzzerPanel = new RpcFuzzerPanel(api);

        setLayout(new BorderLayout(4, 4));
        setBorder(new EmptyBorder(4, 4, 4, 4));

        initUI();
    }

    private void initUI() {
        // Request & Response editors from Montoya
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        historyRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        historyResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // 1. Build GWT Analysis tab content
        JPanel gwtAnalysisPanel = new JPanel(new BorderLayout(4, 4));
        gwtAnalysisPanel.add(createTopPanel(), BorderLayout.NORTH);
        gwtAnalysisPanel.add(createAnalysisSubTabs(), BorderLayout.CENTER);
        gwtAnalysisPanel.add(createBottomStatusPanel(), BorderLayout.SOUTH);

        // 2. Add Top-Level Tabs: GWT Analysis, RPC Deserializer, RPC Fuzzer & Tester
        mainTabbedPane.addTab("GWT Analysis", gwtAnalysisPanel);
        mainTabbedPane.addTab("RPC Deserializer", deserializerPanel);
        mainTabbedPane.addTab("RPC Fuzzer & Tester", fuzzerPanel);

        add(mainTabbedPane, BorderLayout.CENTER);
    }

    // ── Top Toolbar (Target Acquisition) ─────────────────────────────────────

    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 4));
        panel.setBorder(BorderFactory.createCompoundBorder(
                new TitledBorder("Target Acquisition & Scope"),
                new EmptyBorder(4, 6, 4, 6)
        ));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row1.add(new JLabel("Bootstrap URL:"));
        urlField.setToolTipText("Enter .nocache.js bootstrap URL");
        row1.add(urlField);

        row1.add(new JLabel("Permutation URL:"));
        baseField.setToolTipText("Enter {hash}.cache.js permutation URL or base directory override");
        row1.add(baseField);

        analyzeBtn.addActionListener(e -> startAnalysis());
        row1.add(analyzeBtn);

        openFileBtn.setToolTipText("Select offline .cache.js permutation file");
        openFileBtn.addActionListener(e -> openLocalFile());
        row1.add(openFileBtn);

        headersBtn.addActionListener(e -> showHeadersDialog());
        row1.add(headersBtn);

        storageBtn.setToolTipText("View or select directory for GWTMap persistent session storage");
        storageBtn.addActionListener(e -> changeStorageDirectory());
        row1.add(storageBtn);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row2.add(new JLabel("Active Permutation:"));
        permutationCombo.setPreferredSize(new Dimension(240, 24));
        permutationCombo.addActionListener(e -> onPermutationChanged());
        row2.add(permutationCombo);

        passiveMonitorBox.setToolTipText("Automatically detect and extract GWT files passing through Burp Proxy");
        row2.add(passiveMonitorBox);

        JButton resetBtn = new JButton("Reset All");
        resetBtn.addActionListener(e -> resetAll());
        row2.add(resetBtn);

        panel.add(row1, BorderLayout.NORTH);
        panel.add(row2, BorderLayout.SOUTH);
        return panel;
    }

    // ── GWT Analysis Sub-Tabs ────────────────────────────────────────────────
    // Order: HTTP History (1st), Module Info (2nd), Methods & Payloads (3rd), Services & Policies (4th), Deobfuscated Code (5th)

    private JComponent createAnalysisSubTabs() {
        analysisTabbedPane.addTab("HTTP History", createHttpHistoryPanel());
        analysisTabbedPane.addTab("Module Info", createModuleInfoPanel());
        analysisTabbedPane.addTab("Methods & Payloads", createMethodsPanel());
        analysisTabbedPane.addTab("Services & Policies", createServicesPanel());
        analysisTabbedPane.addTab("Deobfuscated Code", createCodeViewerPanel());
        return analysisTabbedPane;
    }

    // ── Tab: HTTP History ────────────────────────────────────────────────────

    private JPanel createHttpHistoryPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        // Top toolbar without Send to Repeater button
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton clearHistoryBtn = new JButton("Clear History");
        clearHistoryBtn.addActionListener(e -> {
            httpHistoryModel.clear();
            dataStore.clearHttpHistory();
            try {
                historyRequestEditor.setRequest(null);
                historyResponseEditor.setResponse(null);
            } catch (Throwable ignored) {}
            saveSession();
        });
        toolbar.add(clearHistoryBtn);

        JLabel historyHint = new JLabel("All HTTP requests and responses executed during target analysis, fragment enumeration, and RPC probes.");
        historyHint.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        toolbar.add(historyHint);

        panel.add(toolbar, BorderLayout.NORTH);

        // Center split: Table on top, Request/Response on bottom
        httpHistoryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        httpHistoryTable.setAutoCreateRowSorter(true);
        httpHistoryTable.getColumnModel().getColumn(0).setPreferredWidth(45);  // #
        httpHistoryTable.getColumnModel().getColumn(1).setPreferredWidth(80);  // Time
        httpHistoryTable.getColumnModel().getColumn(2).setPreferredWidth(130); // Type
        httpHistoryTable.getColumnModel().getColumn(3).setPreferredWidth(60);  // Method
        httpHistoryTable.getColumnModel().getColumn(4).setPreferredWidth(350); // URL
        httpHistoryTable.getColumnModel().getColumn(5).setPreferredWidth(65);  // Status
        httpHistoryTable.getColumnModel().getColumn(6).setPreferredWidth(80);  // Length
        httpHistoryTable.getColumnModel().getColumn(7).setPreferredWidth(80);  // Duration

        httpHistoryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = httpHistoryTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = httpHistoryTable.convertRowIndexToModel(row);
                    GwtHttpHistoryEntry entry = httpHistoryModel.getEntryAt(modelRow);
                    if (entry != null && entry.getRequestResponse() != null) {
                        try {
                            historyRequestEditor.setRequest(entry.getRequestResponse().request());
                        } catch (Throwable ignored) {}
                        try {
                            historyResponseEditor.setResponse(entry.getRequestResponse().response());
                        } catch (Throwable ignored) {}
                    }
                }
            }
        });

        // Right click menu for history table
        JPopupMenu historyPopup = new JPopupMenu();
        JMenuItem repItem = new JMenuItem("Send to Repeater");
        repItem.addActionListener(e -> {
            int row = httpHistoryTable.getSelectedRow();
            if (row >= 0) {
                int modelRow = httpHistoryTable.convertRowIndexToModel(row);
                GwtHttpHistoryEntry entry = httpHistoryModel.getEntryAt(modelRow);
                if (entry != null && entry.getRequestResponse() != null) {
                    api.repeater().sendToRepeater(entry.getRequestResponse().request(), entry.getType());
                }
            }
        });
        historyPopup.add(repItem);

        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        copyUrlItem.addActionListener(e -> {
            int row = httpHistoryTable.getSelectedRow();
            if (row >= 0) {
                int modelRow = httpHistoryTable.convertRowIndexToModel(row);
                GwtHttpHistoryEntry entry = httpHistoryModel.getEntryAt(modelRow);
                if (entry != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getUrl()), null);
                }
            }
        });
        historyPopup.add(copyUrlItem);

        httpHistoryTable.setComponentPopupMenu(historyPopup);
        httpHistoryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = httpHistoryTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !httpHistoryTable.isRowSelected(row)) {
                        httpHistoryTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });

        JTabbedPane historyEditorsTab = new JTabbedPane();
        historyEditorsTab.addTab("Request", historyRequestEditor.uiComponent());
        historyEditorsTab.addTab("Response", historyResponseEditor.uiComponent());

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setTopComponent(new JScrollPane(httpHistoryTable));
        split.setBottomComponent(historyEditorsTab);
        split.setDividerLocation(240);
        split.setResizeWeight(0.4);

        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    // ── Tab: Module Info ─────────────────────────────────────────────────────

    private JPanel createModuleInfoPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        moduleInfoArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        moduleInfoArea.setEditable(false);
        panel.add(new JScrollPane(moduleInfoArea), BorderLayout.CENTER);
        return panel;
    }

    // ── Tab: Methods & Payloads ──────────────────────────────────────────────

    private JPanel createMethodsPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        // Filter & Action Toolbar
        JPanel filterToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        // 1. Search (without (-f))
        filterToolbar.add(new JLabel("Search:"));
        searchField.setToolTipText("Filter by method name, service, signature or URL");
        searchField.getDocument().addDocumentListener(new SimpleDocListener(this::triggerDebouncedFilter));
        filterToolbar.add(searchField);

        // 2. Service Filter
        serviceFilterBtn = new MultiSelectFilterButton(
                "Service", List.of("All Services"), sel -> refreshFilteredViews()
        );
        filterToolbar.add(serviceFilterBtn);

        // 3. Method Selection Dropdown
        filterToolbar.add(new JLabel("Method:"));
        methodSelectCombo.setPreferredSize(new Dimension(280, 24));
        methodSelectCombo.addActionListener(e -> onMethodComboSelected());
        filterToolbar.add(methodSelectCombo);

        // 4. Send Request Button
        JButton sendRequestBtn = new JButton("Send Request");
        sendRequestBtn.setToolTipText("Send HTTP probe request for the selected method and payload");
        sendRequestBtn.addActionListener(e -> probeSelectedMethod());
        filterToolbar.add(sendRequestBtn);

        // 5. Send All Requests Button
        JButton sendAllRequestsBtn = new JButton("Send All Requests");
        sendAllRequestsBtn.setToolTipText("Send HTTP probe requests for all visible methods");
        sendAllRequestsBtn.addActionListener(e -> probeAllVisibleMethods());
        filterToolbar.add(sendAllRequestsBtn);

        // Clear Filters
        JButton resetFiltersBtn = new JButton("Clear Filters");
        resetFiltersBtn.addActionListener(e -> {
            searchField.setText("");
            serviceFilterBtn.clearSelection();
            refreshFilteredViews();
        });
        filterToolbar.add(resetFiltersBtn);

        filterToolbar.add(new JSeparator(SwingConstants.VERTICAL));
        counterLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        filterToolbar.add(counterLabel);

        panel.add(filterToolbar, BorderLayout.NORTH);

        // Center split: Table on top, Editors on bottom
        methodTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        methodTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateSelectedMethodDetails();
                syncMethodComboFromTable();
            }
        });

        // Right-click context menu for methodTable
        JPopupMenu methodPopup = new JPopupMenu();

        JMenuItem probeItem = new JMenuItem("Send Request");
        probeItem.addActionListener(e -> probeSelectedMethod());
        methodPopup.add(probeItem);

        JMenuItem probeAllItem = new JMenuItem("Send All Requests");
        probeAllItem.addActionListener(e -> probeAllVisibleMethods());
        methodPopup.add(probeAllItem);

        methodPopup.addSeparator();

        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        repeaterItem.addActionListener(e -> sendSelectedToRepeater());
        methodPopup.add(repeaterItem);

        JMenuItem intruderItem = new JMenuItem("Send to Intruder");
        intruderItem.addActionListener(e -> sendSelectedToIntruder());
        methodPopup.add(intruderItem);

        methodPopup.addSeparator();

        JMenuItem copyPayloadItem = new JMenuItem("Copy RPC Payload");
        copyPayloadItem.addActionListener(e -> copySelectedRpcPayload());
        methodPopup.add(copyPayloadItem);

        JMenuItem copyReqItem = new JMenuItem("Copy HTTP Request");
        copyReqItem.addActionListener(e -> copySelectedHttpRequest());
        methodPopup.add(copyReqItem);

        methodPopup.addSeparator();

        JMenuItem deserItem = new JMenuItem("Send to Deserializer");
        deserItem.addActionListener(e -> {
            GWTMethod m = getSelectedMethod();
            if (m != null) {
                deserializerPanel.setTargetUrl(m.getFullEndpointUrl());
                loadPayloadIntoDeserializer(m.getMethodRpcCall());
            }
        });
        methodPopup.add(deserItem);

        JMenuItem fuzzerItem = new JMenuItem("Send to Fuzzer");
        fuzzerItem.addActionListener(e -> {
            GWTMethod m = getSelectedMethod();
            if (m != null) {
                loadPayloadIntoFuzzer(m.getFullEndpointUrl(), m.getMethodRpcCall());
            }
        });
        methodPopup.add(fuzzerItem);

        methodTable.setComponentPopupMenu(methodPopup);
        methodTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = methodTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !methodTable.isRowSelected(row)) {
                        methodTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(methodTable);
        tableScroll.setPreferredSize(new Dimension(800, 260));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(tableScroll);
        splitPane.setBottomComponent(createEditorPanel());
        splitPane.setDividerLocation(260);
        splitPane.setResizeWeight(0.45);

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private void onMethodComboSelected() {
        if (isSyncingMethodSelection) return;
        int idx = methodSelectCombo.getSelectedIndex();
        if (idx >= 0 && idx < methodTableModel.getRowCount()) {
            isSyncingMethodSelection = true;
            try {
                methodTable.setRowSelectionInterval(idx, idx);
                methodTable.scrollRectToVisible(methodTable.getCellRect(idx, 0, true));
                updateSelectedMethodDetails();
            } finally {
                isSyncingMethodSelection = false;
            }
        }
    }

    private void syncMethodComboFromTable() {
        if (isSyncingMethodSelection) return;
        int row = methodTable.getSelectedRow();
        if (row >= 0 && row < methodSelectCombo.getItemCount()) {
            isSyncingMethodSelection = true;
            try {
                methodSelectCombo.setSelectedIndex(row);
            } finally {
                isSyncingMethodSelection = false;
            }
        }
    }

    private JPanel createEditorPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        // Sub tabs for editors
        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Request", requestEditor.uiComponent());
        editorTabs.addTab("Response", responseEditor.uiComponent());

        rawRpcArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawRpcArea.setLineWrap(true);
        rawRpcArea.setWrapStyleWord(true);
        editorTabs.addTab("GWT-RPC Payload", new JScrollPane(rawRpcArea));

        evidenceArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        evidenceArea.setEditable(false);
        editorTabs.addTab("Evidence & Types", new JScrollPane(evidenceArea));

        panel.add(editorTabs, BorderLayout.CENTER);
        return panel;
    }

    // ── Tab: Services & Policies ─────────────────────────────────────────────

    private JPanel createServicesPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        serviceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        panel.add(new JScrollPane(serviceTable), BorderLayout.CENTER);

        JLabel hintLabel = new JLabel("Enumerated GWT services and serialization policy strong names (--svc mode).");
        hintLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        panel.add(hintLabel, BorderLayout.SOUTH);
        return panel;
    }

    // ── Tab: Deobfuscated Code ───────────────────────────────────────────────

    private JPanel createCodeViewerPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        // Search Bar at Top
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        searchBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(2, 4, 4, 4)
        ));

        searchBar.add(new JLabel("Find in Code:"));
        codeSearchField.getDocument().addDocumentListener(new SimpleDocListener(this::updateCodeSearch));
        codeSearchField.addActionListener(e -> navigateCodeMatch(1));
        codeSearchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    if (e.isShiftDown()) {
                        navigateCodeMatch(-1);
                    } else {
                        navigateCodeMatch(1);
                    }
                }
            }
        });
        searchBar.add(codeSearchField);

        JButton prevBtn = new JButton("▲");
        prevBtn.setToolTipText("Previous Match (Shift+Enter)");
        prevBtn.addActionListener(e -> navigateCodeMatch(-1));
        searchBar.add(prevBtn);

        JButton nextBtn = new JButton("▼");
        nextBtn.setToolTipText("Next Match (Enter)");
        nextBtn.addActionListener(e -> navigateCodeMatch(1));
        searchBar.add(nextBtn);

        codeMatchCaseBox.addActionListener(e -> updateCodeSearch());
        searchBar.add(codeMatchCaseBox);

        codeMatchCountLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        searchBar.add(codeMatchCountLabel);

        panel.add(searchBar, BorderLayout.NORTH);

        codeViewerArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        codeViewerArea.setEditable(false);
        panel.add(new JScrollPane(codeViewerArea), BorderLayout.CENTER);

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        exportCodeBtn.addActionListener(e -> backupCodeToDisk());
        bottomRow.add(exportCodeBtn);
        panel.add(bottomRow, BorderLayout.SOUTH);

        return panel;
    }

    private void updateCodeSearch() {
        Highlighter highlighter = codeViewerArea.getHighlighter();
        highlighter.removeAllHighlights();
        codeMatchOffsets.clear();
        currentCodeMatchIdx = -1;

        String query = codeSearchField.getText();
        String text = codeViewerArea.getText();
        if (query == null || query.isEmpty() || text == null || text.isEmpty()) {
            codeMatchCountLabel.setText("0 matches");
            return;
        }

        boolean matchCase = codeMatchCaseBox.isSelected();
        String searchText = matchCase ? text : text.toLowerCase();
        String searchQuery = matchCase ? query : query.toLowerCase();

        int index = 0;
        while ((index = searchText.indexOf(searchQuery, index)) >= 0) {
            int end = index + searchQuery.length();
            codeMatchOffsets.add(new int[]{index, end});
            try {
                highlighter.addHighlight(index, end, normalHighlightPainter);
            } catch (Throwable ignored) {}
            index = end;
        }

        if (codeMatchOffsets.isEmpty()) {
            codeMatchCountLabel.setText("0 matches");
        } else {
            currentCodeMatchIdx = 0;
            highlightActiveCodeMatch();
            codeMatchCountLabel.setText("Match 1 of " + codeMatchOffsets.size());
        }
    }

    private void navigateCodeMatch(int direction) {
        if (codeMatchOffsets.isEmpty()) return;
        currentCodeMatchIdx = (currentCodeMatchIdx + direction + codeMatchOffsets.size()) % codeMatchOffsets.size();
        highlightActiveCodeMatch();
        codeMatchCountLabel.setText("Match " + (currentCodeMatchIdx + 1) + " of " + codeMatchOffsets.size());
    }

    private void highlightActiveCodeMatch() {
        if (currentCodeMatchIdx < 0 || currentCodeMatchIdx >= codeMatchOffsets.size()) return;
        Highlighter highlighter = codeViewerArea.getHighlighter();
        highlighter.removeAllHighlights();

        for (int i = 0; i < codeMatchOffsets.size(); i++) {
            int[] pos = codeMatchOffsets.get(i);
            try {
                if (i == currentCodeMatchIdx) {
                    highlighter.addHighlight(pos[0], pos[1], activeHighlightPainter);
                } else {
                    highlighter.addHighlight(pos[0], pos[1], normalHighlightPainter);
                }
            } catch (Throwable ignored) {}
        }

        int[] activePos = codeMatchOffsets.get(currentCodeMatchIdx);
        codeViewerArea.setCaretPosition(activePos[0]);
        try {
            java.awt.geom.Rectangle2D viewRect = codeViewerArea.modelToView2D(activePos[0]);
            if (viewRect != null) {
                codeViewerArea.scrollRectToVisible(viewRect.getBounds());
            }
        } catch (Throwable ignored) {}
    }

    // ── Status Bar & Progress ────────────────────────────────────────────────

    private JPanel createBottomStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 4));
        panel.setBorder(new EmptyBorder(2, 6, 2, 6));

        progressBar.setStringPainted(true);
        progressBar.setVisible(false);

        panel.add(statusLabel, BorderLayout.WEST);
        panel.add(progressBar, BorderLayout.EAST);
        return panel;
    }

    // ── Actions & Workflow ───────────────────────────────────────────────────

    public void setTargetUrl(String url) {
        urlField.setText(url != null ? url.trim() : "");
    }

    public boolean isPassiveMonitorEnabled() {
        return passiveMonitorBox.isSelected();
    }

    public void startAnalysis() {
        String bootstrap = urlField.getText().trim();
        String permutation = baseField.getText().trim();

        if (bootstrap.isEmpty() && permutation.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a Bootstrap URL or Permutation URL.", "GWTMap", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String target = !bootstrap.isEmpty() ? bootstrap : permutation;
        String baseOverride = !permutation.isEmpty() ? permutation : "";

        analyzeBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setMinimum(0);
        progressBar.setMaximum(100);
        progressBar.setValue(0);
        progressBar.setString("0% - Starting analysis...");
        statusLabel.setText("Analyzing: " + target);

        engine.setHttpHistoryListener(entry -> SwingUtilities.invokeLater(() -> {
            httpHistoryModel.addEntry(entry);
            if (entry.getRequestResponse() != null) {
                try {
                    historyRequestEditor.setRequest(entry.getRequestResponse().request());
                    historyResponseEditor.setResponse(entry.getRequestResponse().response());
                } catch (Throwable ignored) {}

                try {
                    if (methodTable.getSelectedRow() < 0) {
                        requestEditor.setRequest(entry.getRequestResponse().request());
                        responseEditor.setResponse(entry.getRequestResponse().response());
                    }
                } catch (Throwable ignored) {}
            }
        }));

        engine.analyzeUrl(target, baseOverride,
                (percent, phase) -> SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(percent);
                    progressBar.setString(percent + "% - " + phase);
                    statusLabel.setText(percent + "%: " + phase);
                }),
                status -> SwingUtilities.invokeLater(() -> statusLabel.setText(status)),
                () -> SwingUtilities.invokeLater(() -> {
                    analyzeBtn.setEnabled(true);
                    progressBar.setVisible(false);
                    onAnalysisFinished();
                })
        );
    }

    public void openLocalFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select local GWT permutation file (*.cache.js) or bootstrap (*.nocache.js)");
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File selectedFile = chooser.getSelectedFile();
            String path = selectedFile.getAbsolutePath();
            if (path.contains(".cache.js") || path.contains(".cache.html")) {
                baseField.setText(path);
                if (urlField.getText().isBlank()) {
                    urlField.setText(path);
                }
            } else {
                urlField.setText(path);
            }

            analyzeBtn.setEnabled(false);
            progressBar.setVisible(true);
            progressBar.setIndeterminate(false);
            progressBar.setMinimum(0);
            progressBar.setMaximum(100);
            progressBar.setValue(0);
            progressBar.setString("0% - Reading file...");
            statusLabel.setText("Loading file: " + selectedFile.getName());

            String baseOverride = baseField.getText().trim();

            engine.analyzeFile(selectedFile, baseOverride,
                    (percent, phase) -> SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(percent);
                        progressBar.setString(percent + "% - " + phase);
                        statusLabel.setText(percent + "%: " + phase);
                    }),
                    status -> SwingUtilities.invokeLater(() -> statusLabel.setText(status)),
                    () -> SwingUtilities.invokeLater(() -> {
                        analyzeBtn.setEnabled(true);
                        progressBar.setVisible(false);
                        onAnalysisFinished();
                    })
            );
        }
    }

    private void onAnalysisFinished() {
        GWTModuleInfo info = dataStore.getModuleInfo();

        if (baseField.getText().isBlank()) {
            baseField.setText(info.getBaseUrl());
        }

        // Update Permutation dropdown
        permutationCombo.removeAllItems();
        List<String> perms = info.getAllPermutations();
        if (perms.isEmpty() && !"Unknown".equals(info.getActivePermutation())) {
            permutationCombo.addItem(info.getActivePermutation());
        } else {
            for (String p : perms) {
                permutationCombo.addItem(p);
            }
        }
        if (!"Unknown".equals(info.getActivePermutation())) {
            permutationCombo.setSelectedItem(info.getActivePermutation());
        }

        // Update Service filter dropdown options
        List<String> serviceNames = new ArrayList<>();
        serviceNames.add("All Services");
        for (GWTService s : dataStore.getAllServices()) {
            if (!serviceNames.contains(s.getServicePath())) {
                serviceNames.add(s.getServicePath());
            }
        }
        int filterIdx = -1;
        Container parent = serviceFilterBtn.getParent();
        if (parent != null) {
            for (int i = 0; i < parent.getComponentCount(); i++) {
                if (parent.getComponent(i) == serviceFilterBtn) {
                    filterIdx = i;
                    break;
                }
            }
            if (filterIdx != -1) {
                parent.remove(serviceFilterBtn);
                serviceFilterBtn = new MultiSelectFilterButton("Service", serviceNames, sel -> refreshFilteredViews());
                parent.add(serviceFilterBtn, filterIdx);
                parent.revalidate();
                parent.repaint();
            }
        }

        // Update Services table
        serviceTableModel.setServices(dataStore.getAllServices());

        // Update Module Info text
        updateModuleInfoDisplay();

        // Update Code viewer
        codeViewerArea.setText(dataStore.getCleanedCode());
        codeViewerArea.setCaretPosition(0);

        // Refresh Methods table & Combo
        refreshFilteredViews();
        statusLabel.setText("Analysis complete! Discovered " + dataStore.getAllMethods().size() + " methods across " + dataStore.getAllServices().size() + " services.");

        // Automatically save snapshot
        saveSession();
    }

    private void onPermutationChanged() {
        String selected = (String) permutationCombo.getSelectedItem();
        if (selected == null || selected.equals(dataStore.getModuleInfo().getActivePermutation())) {
            return;
        }

        String target = urlField.getText().trim();
        if (target.startsWith("http://") || target.startsWith("https://")) {
            String baseUrl = dataStore.getModuleInfo().getBaseUrl();
            String permUrl = baseUrl + selected + ".cache.js";
            urlField.setText(permUrl);
            startAnalysis();
        }
    }

    private void updateModuleInfoDisplay() {
        GWTModuleInfo info = dataStore.getModuleInfo();
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append("  GWT Module Information\n");
        sb.append("================================================================================\n\n");
        sb.append("Target Resource     : ").append(info.getTargetUrl()).append("\n");
        sb.append("GWT Version         : ").append(info.getGwtVersion()).append("\n");
        sb.append("Content-Type        : ").append(info.getContentType()).append("\n");
        sb.append("X-GWT-Module-Base   : ").append(info.getBaseUrl()).append("\n");
        sb.append("X-GWT-Permutation   : ").append(info.getActivePermutation()).append("\n");
        sb.append("RPC Version         : ").append(info.getRpcVersion()).append("\n");
        sb.append("RPC Flags           : ").append(info.getRpcFlags()).append("\n\n");

        sb.append("Discovered Permutations (").append(info.getAllPermutations().size()).append("):\n");
        for (String p : info.getAllPermutations()) {
            sb.append("  * ").append(p).append(p.equals(info.getActivePermutation()) ? " (ACTIVE)" : "").append("\n");
        }
        sb.append("\n");

        sb.append("Deferred JS Fragments (").append(info.getDeferredFragments().size()).append("):\n");
        if (info.getDeferredFragments().isEmpty()) {
            sb.append("  (None or non-fragmented module)\n");
        } else {
            for (String f : info.getDeferredFragments()) {
                sb.append("  + ").append(f).append("\n");
            }
        }
        sb.append("\n");

        sb.append("Discovered Services : ").append(dataStore.getAllServices().size()).append("\n");
        sb.append("Discovered Methods  : ").append(dataStore.getAllMethods().size()).append("\n");

        moduleInfoArea.setText(sb.toString());
        moduleInfoArea.setCaretPosition(0);
    }

    private void triggerDebouncedFilter() {
        filterDebounceTimer.restart();
    }

    private void refreshFilteredViews() {
        String textQuery = searchField.getText();
        Set<String> selectedServices = (serviceFilterBtn != null) ? serviceFilterBtn.getSelected() : Collections.emptySet();

        List<GWTMethod> filtered = dataStore.getFilteredEntries(
                textQuery,
                selectedServices,
                "All",
                Collections.emptySet(),
                url -> true
        );

        methodTableModel.setMethods(filtered);

        // Update Method Selection Dropdown
        isSyncingMethodSelection = true;
        try {
            methodSelectCombo.removeAllItems();
            for (GWTMethod m : filtered) {
                methodSelectCombo.addItem(m.getMethodName() + " (" + String.join(", ", m.getMethodSignature()) + ") - " + m.getServiceCategory());
            }
        } finally {
            isSyncingMethodSelection = false;
        }

        int totalMethods = dataStore.getAllMethods().size();
        int totalServices = dataStore.getAllServices().size();
        long visibleServices = filtered.stream().map(GWTMethod::getServiceCategory).distinct().count();

        counterLabel.setText("Showing " + visibleServices + "/" + totalServices + " Services | "
                + filtered.size() + "/" + totalMethods + " Methods");

        if (!filtered.isEmpty()) {
            methodTable.setRowSelectionInterval(0, 0);
            updateSelectedMethodDetails();
            syncMethodComboFromTable();
        } else {
            try {
                requestEditor.setRequest(null);
            } catch (Throwable ignored) {}
            try {
                responseEditor.setResponse(null);
            } catch (Throwable ignored) {}
            rawRpcArea.setText("");
            evidenceArea.setText("");
        }
    }

    private void updateSelectedMethodDetails() {
        int row = methodTable.getSelectedRow();
        if (row < 0) return;

        int modelRow = methodTable.convertRowIndexToModel(row);
        GWTMethod method = methodTableModel.getMethodAt(modelRow);
        if (method == null) return;

        // Display request in Montoya Request Editor (with markers)
        try {
            HttpRequest req = engine.buildHttpRequest(method, customHeaders, true);
            requestEditor.setRequest(req);
        } catch (Throwable ignored) {}

        // Display response if probed
        try {
            if (method.isProbed() && method.getProbeResponse() != null) {
                responseEditor.setResponse(method.getProbeResponse());
            } else {
                responseEditor.setResponse(null);
            }
        } catch (Throwable ignored) {}

        // Display raw RPC call
        rawRpcArea.setText(method.getMethodRpcCall());
        rawRpcArea.setCaretPosition(0);

        // Display Evidence & Details
        StringBuilder eb = new StringBuilder();
        eb.append("Service Interface : ").append(method.getRmtSvcIntName()).append("\n");
        eb.append("Service Category  : ").append(method.getServiceCategory()).append("\n");
        eb.append("Method Name       : ").append(method.getMethodName()).append("\n");
        eb.append("Parameter Count   : ").append(method.getParamCount()).append("\n");
        eb.append("Endpoint URL      : ").append(method.getFullEndpointUrl()).append("\n");
        eb.append("Serialization Hash: ").append(method.getService() != null ? method.getService().getStrongName() : "Unknown").append("\n");
        eb.append("Signature Types   :\n");
        for (String param : method.getMethodSignature()) {
            eb.append("  - ").append(param).append("\n");
        }
        if (!method.getComplexTypes().isEmpty()) {
            eb.append("\nComplex Types Warning:\n");
            for (String ct : method.getComplexTypes()) {
                eb.append("  ! ").append(ct).append("\n");
            }
        }
        if (method.isProbed()) {
            eb.append("\nProbe Result:\n");
            eb.append("  Status  : ").append(method.getProbeStatusCode()).append("\n");
            eb.append("  Time    : ").append(method.getProbeResponseTimeMs()).append(" ms\n");
            eb.append("  Length  : ").append(method.getProbeResponseLength()).append(" bytes\n");
            eb.append("  Notes   : ").append(method.getProbeNotes()).append("\n");
        }
        evidenceArea.setText(eb.toString());
        evidenceArea.setCaretPosition(0);
    }

    private GWTMethod getSelectedMethod() {
        int row = methodTable.getSelectedRow();
        if (row < 0) return null;
        int modelRow = methodTable.convertRowIndexToModel(row);
        return methodTableModel.getMethodAt(modelRow);
    }

    private void probeSelectedMethod() {
        GWTMethod method = getSelectedMethod();
        if (method == null) {
            JOptionPane.showMessageDialog(this, "Please select a method from the table or dropdown to send request.", "GWTMap", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        statusLabel.setText("Sending Request: " + method.getMethodName() + " (" + method.getFullEndpointUrl() + ")...");
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);

        engine.sendProbe(method, customHeaders, m -> SwingUtilities.invokeLater(() -> {
            progressBar.setVisible(false);
            progressBar.setIndeterminate(false);
            methodTableModel.fireTableDataChanged();
            updateSelectedMethodDetails();
            statusLabel.setText("Request sent for " + m.getMethodName() + ": HTTP " + m.getProbeStatusCode()
                    + " (" + m.getProbeResponseTimeMs() + "ms)");
            saveSession();
        }));
    }

    private void probeAllVisibleMethods() {
        int count = methodTableModel.getRowCount();
        if (count == 0) {
            JOptionPane.showMessageDialog(this, "No visible methods to send requests for.", "GWTMap", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to send requests for all " + count + " visible methods?",
                "Confirm Send All Requests", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        List<GWTMethod> toProbe = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            toProbe.add(methodTableModel.getMethodAt(i));
        }

        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setMinimum(0);
        progressBar.setMaximum(toProbe.size());
        progressBar.setValue(0);
        progressBar.setString("0/" + toProbe.size() + " (0%)");
        statusLabel.setText("Sending requests 0/" + toProbe.size() + "...");

        engine.probeAll(toProbe, customHeaders,
                current -> SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(current);
                    int total = toProbe.size();
                    int pct = total > 0 ? (current * 100 / total) : 0;
                    progressBar.setString(current + "/" + total + " (" + pct + "%)");
                    statusLabel.setText("Sent requests: " + current + "/" + total + " (" + pct + "%)...");
                    methodTableModel.fireTableDataChanged();
                }),
                () -> SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    methodTableModel.fireTableDataChanged();
                    updateSelectedMethodDetails();
                    statusLabel.setText("All requests completed for " + toProbe.size() + " methods!");
                    saveSession();
                    JOptionPane.showMessageDialog(this, "Completed requests for all " + toProbe.size() + " methods!",
                            "GWTMap", JOptionPane.INFORMATION_MESSAGE);
                })
        );
    }

    private void sendSelectedToRepeater() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        HttpRequest req = engine.buildHttpRequest(method, customHeaders, false);
        String tabName = "GWT: " + method.getServiceCategory() + "." + method.getMethodName();
        api.repeater().sendToRepeater(req, tabName);
        statusLabel.setText("Sent " + method.getMethodName() + " to Repeater tab [" + tabName + "]");
    }

    private void sendSelectedToIntruder() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        HttpRequest req = engine.buildHttpRequest(method, customHeaders, true);
        api.intruder().sendToIntruder(req);
        statusLabel.setText("Sent " + method.getMethodName() + " to Intruder (with §markers§)");
    }

    private void copySelectedRpcPayload() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(method.getMethodRpcCall()), null);
        statusLabel.setText("Copied GWT-RPC payload to clipboard");
    }

    private void copySelectedHttpRequest() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        HttpRequest req = engine.buildHttpRequest(method, customHeaders, true);
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(req.toString()), null);
        statusLabel.setText("Copied raw HTTP request to clipboard");
    }

    private void backupCodeToDisk() {
        String code = dataStore.getCleanedCode();
        if (code == null || code.isBlank()) {
            JOptionPane.showMessageDialog(this, "No cleaned code available to export.", "GWTMap", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        String perm = dataStore.getModuleInfo().getActivePermutation();
        String defaultName = System.currentTimeMillis() + "_" + perm + ".cache.js";
        chooser.setSelectedFile(new File(defaultName));

        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                Files.writeString(file.toPath(), code, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this, "Code successfully backed up to:\n" + file.getAbsolutePath(),
                        "Backup Complete", JOptionPane.INFORMATION_MESSAGE);
                statusLabel.setText("Backed up code to: " + file.getAbsolutePath());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error saving file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void showHeadersDialog() {
        JTextArea area = new JTextArea(customHeaders, 10, 35);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(new JLabel("Enter Custom Headers or Cookies (one per line, e.g. Cookie: JSESSIONID=...):"), BorderLayout.NORTH);
        p.add(new JScrollPane(area), BorderLayout.CENTER);

        int opt = JOptionPane.showConfirmDialog(this, p, "Custom Headers & Auth Injection", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (opt == JOptionPane.OK_OPTION) {
            customHeaders = area.getText().trim();
            long lines = customHeaders.isEmpty() ? 0 : Arrays.stream(customHeaders.split("\n")).filter(s -> !s.isBlank()).count();
            headersBtn.setText("Headers & Cookies... (" + lines + ")");
            statusLabel.setText("Configured " + lines + " custom headers/cookies");
            fuzzerPanel.setCustomHeaders(customHeaders);
            updateSelectedMethodDetails();
            saveSession();
        }
    }

    public void changeStorageDirectory() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select GWTMap Session Storage Directory");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);

        File current = persistenceManager.getStorageDirectory();
        if (current != null && current.exists()) {
            chooser.setSelectedFile(current);
        }

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File chosen = chooser.getSelectedFile();
            if (chosen != null) {
                persistenceManager.setStorageDirectory(chosen);
                statusLabel.setText("Storage directory set to: " + chosen.getAbsolutePath());
                saveSession();
            }
        }
    }

    public void resetAll() {
        dataStore.reset();
        engine.resetHistoryCounter();
        urlField.setText("");
        baseField.setText("");
        searchField.setText("");
        codeSearchField.setText("");
        permutationCombo.removeAllItems();
        methodSelectCombo.removeAllItems();
        customHeaders = "";
        fuzzerPanel.setCustomHeaders("");
        headersBtn.setText("Headers & Cookies... (0)");
        serviceTableModel.setServices(Collections.emptyList());
        methodTableModel.setMethods(Collections.emptyList());
        httpHistoryModel.clear();
        try {
            historyRequestEditor.setRequest(null);
            historyResponseEditor.setResponse(null);
        } catch (Throwable ignored) {}
        try {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
        } catch (Throwable ignored) {}
        rawRpcArea.setText("");
        evidenceArea.setText("");
        moduleInfoArea.setText("");
        codeViewerArea.setText("");
        counterLabel.setText("Showing 0/0 Services | 0/0 Methods");
        statusLabel.setText("Reset complete. Ready.");
        persistenceManager.clear();
    }

    public void saveSession() {
        persistenceManager.save(dataStore, urlField.getText(), baseField.getText(), customHeaders);
    }

    public void loadSavedSession() {
        GWTMapPersistenceManager.SessionSnapshot snap = persistenceManager.load(dataStore);
        if (snap != null) {
            if (snap.targetUrl != null && !snap.targetUrl.isBlank()) {
                urlField.setText(snap.targetUrl);
            }
            if (snap.permutationUrl != null && !snap.permutationUrl.isBlank()) {
                baseField.setText(snap.permutationUrl);
            }
            if (snap.customHeaders != null && !snap.customHeaders.isBlank()) {
                customHeaders = snap.customHeaders;
                long lines = Arrays.stream(customHeaders.split("\n")).filter(s -> !s.isBlank()).count();
                headersBtn.setText("Headers & Cookies... (" + lines + ")");
                fuzzerPanel.setCustomHeaders(customHeaders);
            }

            // Restore HTTP History table model
            httpHistoryModel.clear();
            for (GwtHttpHistoryEntry entry : dataStore.getHttpHistory()) {
                httpHistoryModel.addEntry(entry);
            }

            // Restore UI views
            onAnalysisFinished();
            statusLabel.setText("Restored saved session from: " + persistenceManager.getSessionFile().getAbsolutePath());
        }
    }

    public void loadPayloadIntoDeserializer(String rawPayload) {
        if (rawPayload != null) {
            deserializerPanel.setPayload(rawPayload);
            mainTabbedPane.setSelectedComponent(deserializerPanel);
        }
    }

    public void loadPayloadIntoFuzzer(String url, String rawPayload) {
        if (url != null) {
            fuzzerPanel.setTargetUrl(url);
        }
        if (rawPayload != null) {
            fuzzerPanel.setBaselineBody(rawPayload);
        }
        fuzzerPanel.setCustomHeaders(customHeaders);
        mainTabbedPane.setSelectedComponent(fuzzerPanel);
    }

    // ── Helper DocumentListener ──────────────────────────────────────────────

    private static class SimpleDocListener implements DocumentListener {
        private final Runnable onChange;
        SimpleDocListener(Runnable onChange) { this.onChange = onChange; }
        public void insertUpdate(DocumentEvent e) { onChange.run(); }
        public void removeUpdate(DocumentEvent e) { onChange.run(); }
        public void changedUpdate(DocumentEvent e) { onChange.run(); }
    }
}
