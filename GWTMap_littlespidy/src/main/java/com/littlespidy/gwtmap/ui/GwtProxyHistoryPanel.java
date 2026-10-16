// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.gwtmap.model.GWTRpcPayload;
import com.littlespidy.gwtmap.model.GWTRpcResponse;
import com.littlespidy.gwtmap.model.GwtProxyHistoryEntry;
import com.littlespidy.gwtmap.parser.GWTRpcDeserializer;
import com.littlespidy.gwtmap.parser.GWTRpcResponseDeserializer;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Suite tab panel displaying all HTTP Proxy history enriched with GWT-RPC metadata.
 * Provides multi-criteria filtering (Method Name, Service, URL/Text, Status, Only GWT-RPC)
 * and deep split Request, Response, GWT Response, and GWT Request inspection.
 *
 * @author littlespidy
 */
public class GwtProxyHistoryPanel extends JPanel {

    private final MontoyaApi api;
    private final GWTMapTab mainTab;

    private final List<GwtProxyHistoryEntry> masterEntries = new ArrayList<>();
    private final GwtProxyHistoryTableModel tableModel = new GwtProxyHistoryTableModel();
    private final JTable proxyTable = new JTable(tableModel);

    // Toolbar Controls & Filters
    private final JButton fetchBtn = new JButton("Fetch / Refresh from Proxy History");
    private final JCheckBox liveCaptureBox = new JCheckBox("Live Proxy Capture", true);
    private final JTextField searchField = new JTextField(16);
    private final JComboBox<String> methodFilterCombo = new JComboBox<>();
    private final JComboBox<String> serviceFilterCombo = new JComboBox<>();
    private final JComboBox<String> statusFilterCombo = new JComboBox<>();
    private final JCheckBox onlyGwtBox = new JCheckBox("Only GWT-RPC Traffic", true);
    private final JButton clearFiltersBtn = new JButton("Clear Filters");
    private final JButton clearHistoryBtn = new JButton("Clear");
    private final JLabel counterLabel = new JLabel("Showing 0/0 requests");

    // Split Editors
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private final JTextArea gwtRequestArea = new JTextArea();

    // Embedded GWT Response components
    private final JPanel gwtResponseBanner = new JPanel(new BorderLayout(6, 4));
    private final JLabel gwtResponseStatusLabel = new JLabel("GWT Response: Not analyzed");
    private final JTextArea gwtResponseStructuredArea = new JTextArea();
    private final DefaultTableModel gwtStringTableModel;
    private final JTable gwtStringTable;
    private final JTextArea gwtResponseRawArea = new JTextArea();

    // Debounce timer for filtering
    private final javax.swing.Timer filterDebounceTimer = new javax.swing.Timer(250, e -> refreshFilteredViews());
    {
        filterDebounceTimer.setRepeats(false);
    }

    private final AtomicInteger sequenceCounter = new AtomicInteger(1);
    private boolean isUpdatingCombos = false;

    public GwtProxyHistoryPanel(MontoyaApi api, GWTMapTab mainTab) {
        this.api = api;
        this.mainTab = mainTab;

        setLayout(new BorderLayout(4, 4));
        setBorder(new EmptyBorder(6, 6, 6, 6));

        // Setup String Table model
        String[] cols = {"#", "Type / Category", "String Value"};
        gwtStringTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        gwtStringTable = new JTable(gwtStringTableModel);
        gwtStringTable.setAutoCreateRowSorter(true);
        gwtStringTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        gwtStringTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        gwtStringTable.getColumnModel().getColumn(2).setPreferredWidth(550);

        initUI();
        registerLiveProxyHandler();
    }

    private void initUI() {
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // Top Toolbar
        JPanel topContainer = new JPanel(new BorderLayout(4, 4));

        // Row 1: Actions & Status
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        fetchBtn.setToolTipText("Pull all existing requests and responses from Burp Suite's HTTP Proxy history");
        fetchBtn.addActionListener(e -> fetchHistoryFromProxy());
        actionRow.add(fetchBtn);

        liveCaptureBox.setToolTipText("Automatically capture new HTTP proxy transactions in real time");
        actionRow.add(liveCaptureBox);

        clearHistoryBtn.setToolTipText("Clear all displayed proxy history items");
        clearHistoryBtn.addActionListener(e -> clearAllHistory());
        actionRow.add(clearHistoryBtn);

        actionRow.add(new JSeparator(SwingConstants.VERTICAL));
        counterLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        actionRow.add(counterLabel);

        topContainer.add(actionRow, BorderLayout.NORTH);

        // Row 2: Filtering Controls
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        filterRow.add(new JLabel("Search:"));
        searchField.setToolTipText("Filter by URL, GWT Method Name, Service, or Request/Response text");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { filterDebounceTimer.restart(); }
            @Override
            public void removeUpdate(DocumentEvent e) { filterDebounceTimer.restart(); }
            @Override
            public void changedUpdate(DocumentEvent e) { filterDebounceTimer.restart(); }
        });
        filterRow.add(searchField);

        filterRow.add(new JLabel("Method:"));
        methodFilterCombo.setPreferredSize(new Dimension(180, 24));
        methodFilterCombo.addItem("All Methods");
        methodFilterCombo.addActionListener(e -> {
            if (!isUpdatingCombos) refreshFilteredViews();
        });
        filterRow.add(methodFilterCombo);

        filterRow.add(new JLabel("Service:"));
        serviceFilterCombo.setPreferredSize(new Dimension(180, 24));
        serviceFilterCombo.addItem("All Services");
        serviceFilterCombo.addActionListener(e -> {
            if (!isUpdatingCombos) refreshFilteredViews();
        });
        filterRow.add(serviceFilterCombo);

        filterRow.add(new JLabel("Status:"));
        statusFilterCombo.addItem("All Status");
        statusFilterCombo.addItem("2xx Success");
        statusFilterCombo.addItem("3xx Redirection");
        statusFilterCombo.addItem("4xx Client Error");
        statusFilterCombo.addItem("5xx Server Error");
        statusFilterCombo.addActionListener(e -> {
            if (!isUpdatingCombos) refreshFilteredViews();
        });
        filterRow.add(statusFilterCombo);

        onlyGwtBox.setToolTipText("When checked, only shows requests classified as GWT-RPC");
        onlyGwtBox.addActionListener(e -> refreshFilteredViews());
        filterRow.add(onlyGwtBox);

        clearFiltersBtn.addActionListener(e -> resetFilters());
        filterRow.add(clearFiltersBtn);

        topContainer.add(filterRow, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // Center split: Table on top, Editors on bottom
        proxyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        proxyTable.setAutoCreateRowSorter(true);
        proxyTable.getColumnModel().getColumn(0).setPreferredWidth(45);  // #
        proxyTable.getColumnModel().getColumn(1).setPreferredWidth(75);  // Time
        proxyTable.getColumnModel().getColumn(2).setPreferredWidth(60);  // Method
        proxyTable.getColumnModel().getColumn(3).setPreferredWidth(140); // Method Name
        proxyTable.getColumnModel().getColumn(4).setPreferredWidth(160); // Service
        proxyTable.getColumnModel().getColumn(5).setPreferredWidth(300); // URL
        proxyTable.getColumnModel().getColumn(6).setPreferredWidth(65);  // Status
        proxyTable.getColumnModel().getColumn(7).setPreferredWidth(75);  // Length
        proxyTable.getColumnModel().getColumn(8).setPreferredWidth(100); // MIME Type
        proxyTable.getColumnModel().getColumn(9).setPreferredWidth(75);  // Duration

        proxyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = proxyTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = proxyTable.convertRowIndexToModel(row);
                    GwtProxyHistoryEntry entry = tableModel.getEntryAt(modelRow);
                    updateEditorViews(entry);
                }
            }
        });

        // Context menu
        setupContextMenu();

        JScrollPane tableScroll = new JScrollPane(proxyTable);

        // Lower Tabbed Editors
        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Request", requestEditor.uiComponent());
        editorTabs.addTab("Response", responseEditor.uiComponent());
        editorTabs.addTab("GWT Response", createGwtResponsePanel());

        gwtRequestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        gwtRequestArea.setEditable(false);
        editorTabs.addTab("GWT Request (AST)", new JScrollPane(gwtRequestArea));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(tableScroll);
        splitPane.setBottomComponent(editorTabs);
        splitPane.setDividerLocation(260);
        splitPane.setResizeWeight(0.45);

        add(splitPane, BorderLayout.CENTER);
    }

    private JPanel createGwtResponsePanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(4, 4, 4, 4));

        gwtResponseBanner.setBorder(new CompoundBorder(
                new LineBorder(Color.GRAY, 1),
                new EmptyBorder(4, 8, 4, 8)
        ));
        gwtResponseStatusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        gwtResponseBanner.add(gwtResponseStatusLabel, BorderLayout.CENTER);

        JPanel btnGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton copySummaryBtn = new JButton("Copy Structured View");
        copySummaryBtn.addActionListener(e -> {
            if (gwtResponseStructuredArea.getText() != null && !gwtResponseStructuredArea.getText().isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(gwtResponseStructuredArea.getText()), null);
            }
        });
        btnGroup.add(copySummaryBtn);

        JButton copyRawBtn = new JButton("Copy Raw Body");
        copyRawBtn.addActionListener(e -> {
            if (gwtResponseRawArea.getText() != null && !gwtResponseRawArea.getText().isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(gwtResponseRawArea.getText()), null);
            }
        });
        btnGroup.add(copyRawBtn);
        gwtResponseBanner.add(btnGroup, BorderLayout.EAST);

        panel.add(gwtResponseBanner, BorderLayout.NORTH);

        JTabbedPane respSubTabs = new JTabbedPane();
        gwtResponseStructuredArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        gwtResponseStructuredArea.setEditable(false);
        respSubTabs.addTab("Structured View", new JScrollPane(gwtResponseStructuredArea));

        respSubTabs.addTab("String Table", new JScrollPane(gwtStringTable));

        gwtResponseRawArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        gwtResponseRawArea.setEditable(false);
        respSubTabs.addTab("Raw Response", new JScrollPane(gwtResponseRawArea));

        panel.add(respSubTabs, BorderLayout.CENTER);
        return panel;
    }

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem repItem = new JMenuItem("Send to Repeater");
        repItem.addActionListener(e -> {
            GwtProxyHistoryEntry entry = getSelectedEntry();
            if (entry != null && entry.getProxyItem() != null && entry.getProxyItem().finalRequest() != null) {
                String tabName = !entry.getMethodName().isEmpty() ? entry.getMethodName() : "Proxy GWT";
                api.repeater().sendToRepeater(entry.getProxyItem().finalRequest(), tabName);
            }
        });
        popup.add(repItem);

        JMenuItem intruderItem = new JMenuItem("Send to Intruder");
        intruderItem.addActionListener(e -> {
            GwtProxyHistoryEntry entry = getSelectedEntry();
            if (entry != null && entry.getProxyItem() != null && entry.getProxyItem().finalRequest() != null) {
                api.intruder().sendToIntruder(entry.getProxyItem().finalRequest());
            }
        });
        popup.add(intruderItem);

        popup.addSeparator();

        JMenuItem deserItem = new JMenuItem("Send to GWTMap Deserializer");
        deserItem.addActionListener(e -> {
            GwtProxyHistoryEntry entry = getSelectedEntry();
            if (entry != null && entry.getProxyItem() != null && entry.getProxyItem().request() != null) {
                String body = entry.getProxyItem().request().bodyToString();
                if (mainTab != null) {
                    mainTab.loadPayloadIntoDeserializer(body);
                }
            }
        });
        popup.add(deserItem);

        JMenuItem fuzzerItem = new JMenuItem("Send to GWTMap Fuzzer");
        fuzzerItem.addActionListener(e -> {
            GwtProxyHistoryEntry entry = getSelectedEntry();
            if (entry != null && entry.getProxyItem() != null && entry.getProxyItem().request() != null) {
                String url = entry.getUrl();
                String body = entry.getProxyItem().request().bodyToString();
                if (mainTab != null) {
                    mainTab.loadPayloadIntoFuzzer(url, body);
                }
            }
        });
        popup.add(fuzzerItem);

        popup.addSeparator();

        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        copyUrlItem.addActionListener(e -> {
            GwtProxyHistoryEntry entry = getSelectedEntry();
            if (entry != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getUrl()), null);
            }
        });
        popup.add(copyUrlItem);

        JMenuItem copyMethodItem = new JMenuItem("Copy GWT Method Name");
        copyMethodItem.addActionListener(e -> {
            GwtProxyHistoryEntry entry = getSelectedEntry();
            if (entry != null && !entry.getMethodName().isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getMethodName()), null);
            }
        });
        popup.add(copyMethodItem);

        JMenuItem copyRpcItem = new JMenuItem("Copy RPC Payload");
        copyRpcItem.addActionListener(e -> {
            GwtProxyHistoryEntry entry = getSelectedEntry();
            if (entry != null && entry.getProxyItem() != null && entry.getProxyItem().request() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(entry.getProxyItem().request().bodyToString()), null);
            }
        });
        popup.add(copyRpcItem);

        proxyTable.setComponentPopupMenu(popup);
        proxyTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = proxyTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !proxyTable.isRowSelected(row)) {
                        proxyTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });
    }

    private GwtProxyHistoryEntry getSelectedEntry() {
        int row = proxyTable.getSelectedRow();
        if (row >= 0) {
            int modelRow = proxyTable.convertRowIndexToModel(row);
            return tableModel.getEntryAt(modelRow);
        }
        return null;
    }

    private void updateEditorViews(GwtProxyHistoryEntry entry) {
        if (entry == null || entry.getProxyItem() == null) {
            clearEditorViews();
            return;
        }

        HttpRequest req = entry.getProxyItem().finalRequest() != null ? entry.getProxyItem().finalRequest() : entry.getProxyItem().request();
        HttpResponse resp = entry.getProxyItem().originalResponse() != null ? entry.getProxyItem().originalResponse() : entry.getProxyItem().response();

        try {
            requestEditor.setRequest(req);
        } catch (Throwable ignored) {}

        try {
            responseEditor.setResponse(resp);
        } catch (Throwable ignored) {}

        // GWT Request AST
        if (req != null) {
            String reqBody = req.bodyToString();
            if (reqBody != null && (reqBody.contains("|0|") || reqBody.matches("^[0-9]+\\|[0-9]+\\|.*"))) {
                GWTRpcPayload parsed = GWTRpcDeserializer.deserialize(reqBody);
                gwtRequestArea.setText(GWTRpcDeserializer.formatAstTree(parsed));
            } else {
                gwtRequestArea.setText("Non-GWT RPC request or payload empty.");
            }
            gwtRequestArea.setCaretPosition(0);
        }

        // GWT Response
        if (resp != null) {
            String respBody = resp.bodyToString();
            gwtResponseRawArea.setText(respBody != null ? respBody : "");
            gwtResponseRawArea.setCaretPosition(0);

            if (respBody != null && GWTRpcResponseDeserializer.isGwtResponse(respBody)) {
                GWTRpcResponse parsedResp = GWTRpcResponseDeserializer.deserialize(respBody);
                gwtResponseStructuredArea.setText(parsedResp.getFormattedSummary());
                gwtResponseStructuredArea.setCaretPosition(0);

                gwtStringTableModel.setRowCount(0);
                for (int i = 0; i < parsedResp.getStringTable().size(); i++) {
                    String val = parsedResp.getStringTable().get(i);
                    String tag = GWTRpcResponseDeserializer.isTypeSignature(val) ? "Type Signature" : "String Value";
                    gwtStringTableModel.addRow(new Object[]{i + 1, tag, val});
                }

                if (parsedResp.isSuccess()) {
                    String retInfo = !parsedResp.getReturnType().isEmpty() ? " [" + parsedResp.getReturnType() + "]" : "";
                    gwtResponseStatusLabel.setText("[OK] GWT-RPC Return Value: Success" + retInfo);
                    gwtResponseStatusLabel.setForeground(new Color(25, 110, 25));
                    gwtResponseBanner.setBackground(new Color(235, 250, 235));
                    gwtResponseBanner.setBorder(new LineBorder(new Color(40, 167, 69), 1));
                } else if (parsedResp.isException()) {
                    String exInfo = !parsedResp.getExceptionType().isEmpty() ? parsedResp.getExceptionType() : "Server Exception";
                    String msg = !parsedResp.getExceptionMessage().isEmpty() ? " - " + parsedResp.getExceptionMessage() : "";
                    gwtResponseStatusLabel.setText("[EX] GWT Exception: " + exInfo + msg);
                    gwtResponseStatusLabel.setForeground(new Color(160, 25, 25));
                    gwtResponseBanner.setBackground(new Color(255, 235, 235));
                    gwtResponseBanner.setBorder(new LineBorder(new Color(220, 53, 69), 1));
                }
            } else {
                gwtResponseStructuredArea.setText("Non-GWT response or unrecognized format.\n\nRaw body preserved in Raw Response tab.");
                gwtResponseStatusLabel.setText("[?] GWT Response: Not a recognized GWT-RPC response");
                gwtResponseStatusLabel.setForeground(Color.DARK_GRAY);
                gwtResponseBanner.setBackground(UIManager.getColor("Panel.background"));
                gwtResponseBanner.setBorder(new LineBorder(Color.GRAY, 1));
                gwtStringTableModel.setRowCount(0);
            }
        }
    }

    private void clearEditorViews() {
        try {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
        } catch (Throwable ignored) {}
        gwtRequestArea.setText("");
        gwtResponseStructuredArea.setText("");
        gwtResponseRawArea.setText("");
        gwtStringTableModel.setRowCount(0);
        gwtResponseStatusLabel.setText("GWT Response: None");
        gwtResponseBanner.setBackground(UIManager.getColor("Panel.background"));
        gwtResponseBanner.setBorder(new LineBorder(Color.GRAY, 1));
    }

    // ── Data Acquisition & Live Proxy Hook ───────────────────────────────────

    public void fetchHistoryFromProxy() {
        fetchBtn.setEnabled(false);
        counterLabel.setText("Fetching proxy history...");

        SwingWorker<List<GwtProxyHistoryEntry>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<GwtProxyHistoryEntry> doInBackground() {
                List<GwtProxyHistoryEntry> parsedList = new ArrayList<>();
                try {
                    List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
                    if (proxyHistory == null) return parsedList;

                    int seq = 1;
                    for (ProxyHttpRequestResponse item : proxyHistory) {
                        GwtProxyHistoryEntry entry = parseProxyItem(seq++, item);
                        if (entry != null) {
                            parsedList.add(entry);
                        }
                    }
                } catch (Throwable t) {
                    if (api != null) {
                        api.logging().logToError("[GWTMap] Error fetching proxy history: " + t.getMessage());
                    }
                }
                return parsedList;
            }

            @Override
            protected void done() {
                try {
                    List<GwtProxyHistoryEntry> results = get();
                    synchronized (masterEntries) {
                        masterEntries.clear();
                        masterEntries.addAll(results);
                        sequenceCounter.set(results.size() + 1);
                    }
                    updateFilterOptions();
                    refreshFilteredViews();
                } catch (Throwable ignored) {
                } finally {
                    fetchBtn.setEnabled(true);
                }
            }
        };
        worker.execute();
    }

    private void registerLiveProxyHandler() {
        try {
            api.proxy().registerResponseHandler(new ProxyResponseHandler() {
                @Override
                public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                    return ProxyResponseReceivedAction.continueWith(interceptedResponse);
                }

                @Override
                public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                    if (liveCaptureBox.isSelected()) {
                        try {
                            GwtProxyHistoryEntry entry = parseInterceptedResponse(sequenceCounter.getAndIncrement(), interceptedResponse);
                            if (entry != null) {
                                SwingUtilities.invokeLater(() -> {
                                    synchronized (masterEntries) {
                                        masterEntries.add(entry);
                                    }
                                    addFilterOptionIfNew(entry.getMethodName(), entry.getService());
                                    if (matchesFilter(entry)) {
                                        tableModel.addEntry(entry);
                                        updateCounterLabel();
                                    }
                                });
                            }
                        } catch (Throwable ignored) {}
                    }
                    return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
                }
            });
        } catch (Throwable t) {
            if (api != null) {
                api.logging().logToError("[GWTMap] Could not register live proxy response handler: " + t.getMessage());
            }
        }
    }

    private GwtProxyHistoryEntry parseProxyItem(int seq, ProxyHttpRequestResponse item) {
        if (item == null) return null;

        String timestamp = "";
        try {
            if (item.time() != null) {
                timestamp = item.time().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
            }
        } catch (Throwable ignored) {}
        if (timestamp.isEmpty()) {
            timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        }

        String httpMethod = item.request() != null && item.request().method() != null ? item.request().method() : "GET";
        String url = item.request() != null && item.request().url() != null ? item.request().url() : "";
        int statusCode = 0;
        int responseLength = 0;
        String mimeType = "";
        long durationMs = -1;

        try {
            if (item.response() != null) {
                statusCode = item.response().statusCode();
                if (item.response().body() != null) {
                    responseLength = item.response().body().length();
                }
            }
            if (item.mimeType() != null) {
                mimeType = item.mimeType().name();
            }
            if (item.timingData() != null && item.timingData().timeBetweenRequestSentAndEndOfResponse() != null) {
                durationMs = item.timingData().timeBetweenRequestSentAndEndOfResponse().toMillis();
            }
        } catch (Throwable ignored) {}

        // GWT RPC extraction
        String methodName = "";
        String service = "";
        boolean isGwt = false;

        try {
            if (item.request() != null) {
                String body = item.request().bodyToString();
                if (body != null && !body.isBlank()) {
                    String trimmed = body.trim();
                    if (trimmed.matches("^[0-9]+\\|[0-9]+\\|.*") || trimmed.contains("|0|") || trimmed.contains("|1|")) {
                        isGwt = true;
                        GWTRpcPayload parsed = GWTRpcDeserializer.deserialize(trimmed);
                        if (parsed.getMethodName() != null && !parsed.getMethodName().isEmpty()) {
                            methodName = parsed.getMethodName();
                        }
                        if (parsed.getServiceInterface() != null && !parsed.getServiceInterface().isEmpty()) {
                            service = parsed.getServiceInterface();
                        }
                    }
                }
            }

            if (!isGwt && item.response() != null) {
                String respBody = item.response().bodyToString();
                if (respBody != null && GWTRpcResponseDeserializer.isGwtResponse(respBody)) {
                    isGwt = true;
                }
            }
        } catch (Throwable ignored) {}

        return new GwtProxyHistoryEntry(
                seq, timestamp, httpMethod, methodName, service, url, statusCode,
                responseLength, mimeType, durationMs, isGwt, item
        );
    }

    private GwtProxyHistoryEntry parseInterceptedResponse(int seq, InterceptedResponse response) {
        if (response == null) return null;

        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        HttpRequest req = response.initiatingRequest() != null ? response.initiatingRequest() : response.request();
        String httpMethod = req != null && req.method() != null ? req.method() : "GET";
        String url = req != null && req.url() != null ? req.url() : "";
        int statusCode = response.statusCode();
        int responseLength = response.body() != null ? response.body().length() : 0;
        String mimeType = response.mimeType() != null ? response.mimeType().name() : "";
        long durationMs = -1;

        String methodName = "";
        String service = "";
        boolean isGwt = false;

        if (req != null) {
            String body = req.bodyToString();
            if (body != null && !body.isBlank()) {
                String trimmed = body.trim();
                if (trimmed.matches("^[0-9]+\\|[0-9]+\\|.*") || trimmed.contains("|0|") || trimmed.contains("|1|")) {
                    isGwt = true;
                    GWTRpcPayload parsed = GWTRpcDeserializer.deserialize(trimmed);
                    if (parsed.getMethodName() != null && !parsed.getMethodName().isEmpty()) {
                        methodName = parsed.getMethodName();
                    }
                    if (parsed.getServiceInterface() != null && !parsed.getServiceInterface().isEmpty()) {
                        service = parsed.getServiceInterface();
                    }
                }
            }
        }

        if (!isGwt) {
            String respBody = response.bodyToString();
            if (respBody != null && GWTRpcResponseDeserializer.isGwtResponse(respBody)) {
                isGwt = true;
            }
        }

        // Wrap into ProxyHttpRequestResponse adapter
        ProxyHttpRequestResponse proxyItem = createProxyItemAdapter(req, response, url, httpMethod);

        return new GwtProxyHistoryEntry(
                seq, timestamp, httpMethod, methodName, service, url, statusCode,
                responseLength, mimeType, durationMs, isGwt, proxyItem
        );
    }

    @SuppressWarnings("removal")
    private ProxyHttpRequestResponse createProxyItemAdapter(HttpRequest req, HttpResponse resp, String url, String method) {
        final HttpRequest finalReq = req;
        final HttpResponse finalResp = resp;
        final String finalUrl = url;
        final String finalMethod = method;

        return new ProxyHttpRequestResponse() {
            @Override public HttpRequest request() { return finalReq; }
            @Override public HttpRequest finalRequest() { return finalReq; }
            @Override public HttpResponse response() { return finalResp; }
            @Override public HttpResponse originalResponse() { return finalResp; }
            @Override public burp.api.montoya.core.Annotations annotations() { return burp.api.montoya.core.Annotations.annotations(); }
            @Override public burp.api.montoya.http.HttpService httpService() { return finalReq != null ? finalReq.httpService() : null; }
            @Override public String url() { return finalUrl; }
            @Override public String method() { return finalMethod; }
            @Override public String path() { return finalReq != null ? finalReq.path() : ""; }
            @Override public String host() { return finalReq != null ? finalReq.httpService().host() : ""; }
            @Override public int port() { return finalReq != null ? finalReq.httpService().port() : 80; }
            @Override public boolean secure() { return finalReq != null && finalReq.httpService().secure(); }
            @Override public String httpServiceString() { return finalReq != null ? finalReq.httpService().toString() : ""; }
            @Override public String requestHttpVersion() { return finalReq != null ? finalReq.httpVersion() : "HTTP/1.1"; }
            @Override public String requestBody() { return finalReq != null ? finalReq.bodyToString() : ""; }
            @Override public boolean edited() { return false; }
            @Override public java.time.ZonedDateTime time() { return java.time.ZonedDateTime.now(); }
            @Override public int listenerPort() { return 8080; }
            @Override public burp.api.montoya.http.message.MimeType mimeType() { return finalResp != null ? finalResp.mimeType() : burp.api.montoya.http.message.MimeType.NONE; }
            @Override public boolean hasResponse() { return finalResp != null; }
            @Override public boolean contains(String s, boolean b) { return false; }
            @Override public boolean contains(java.util.regex.Pattern pattern) { return false; }
            @Override public burp.api.montoya.http.handler.TimingData timingData() { return null; }
        };
    }

    // ── Filtering Logic ──────────────────────────────────────────────────────

    private synchronized void updateFilterOptions() {
        isUpdatingCombos = true;
        try {
            String curMethod = (String) methodFilterCombo.getSelectedItem();
            String curService = (String) serviceFilterCombo.getSelectedItem();

            Set<String> methods = new TreeSet<>();
            Set<String> services = new TreeSet<>();

            for (GwtProxyHistoryEntry e : masterEntries) {
                if (!e.getMethodName().isEmpty()) methods.add(e.getMethodName());
                if (!e.getService().isEmpty()) services.add(e.getService());
            }

            methodFilterCombo.removeAllItems();
            methodFilterCombo.addItem("All Methods");
            for (String m : methods) methodFilterCombo.addItem(m);
            if (curMethod != null && methods.contains(curMethod)) {
                methodFilterCombo.setSelectedItem(curMethod);
            }

            serviceFilterCombo.removeAllItems();
            serviceFilterCombo.addItem("All Services");
            for (String s : services) serviceFilterCombo.addItem(s);
            if (curService != null && services.contains(curService)) {
                serviceFilterCombo.setSelectedItem(curService);
            }
        } finally {
            isUpdatingCombos = false;
        }
    }

    private synchronized void addFilterOptionIfNew(String method, String service) {
        if (method != null && !method.isEmpty()) {
            boolean found = false;
            for (int i = 0; i < methodFilterCombo.getItemCount(); i++) {
                if (method.equals(methodFilterCombo.getItemAt(i))) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                methodFilterCombo.addItem(method);
            }
        }

        if (service != null && !service.isEmpty()) {
            boolean found = false;
            for (int i = 0; i < serviceFilterCombo.getItemCount(); i++) {
                if (service.equals(serviceFilterCombo.getItemAt(i))) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                serviceFilterCombo.addItem(service);
            }
        }
    }

    public synchronized void refreshFilteredViews() {
        List<GwtProxyHistoryEntry> filtered = new ArrayList<>();
        synchronized (masterEntries) {
            for (GwtProxyHistoryEntry entry : masterEntries) {
                if (matchesFilter(entry)) {
                    filtered.add(entry);
                }
            }
        }
        tableModel.setEntries(filtered);
        updateCounterLabel();
    }

    private boolean matchesFilter(GwtProxyHistoryEntry entry) {
        if (entry == null) return false;

        // 1. Only GWT filter
        if (onlyGwtBox.isSelected() && !entry.isGwtRpc()) {
            return false;
        }

        // 2. Method filter
        String selMethod = (String) methodFilterCombo.getSelectedItem();
        if (selMethod != null && !selMethod.equals("All Methods")) {
            if (!entry.getMethodName().equalsIgnoreCase(selMethod)) {
                return false;
            }
        }

        // 3. Service filter
        String selService = (String) serviceFilterCombo.getSelectedItem();
        if (selService != null && !selService.equals("All Services")) {
            if (!entry.getService().equalsIgnoreCase(selService)) {
                return false;
            }
        }

        // 4. Status code filter
        int statusIdx = statusFilterCombo.getSelectedIndex();
        int code = entry.getStatusCode();
        if (statusIdx == 1 && (code < 200 || code >= 300)) return false; // 2xx
        if (statusIdx == 2 && (code < 300 || code >= 400)) return false; // 3xx
        if (statusIdx == 3 && (code < 400 || code >= 500)) return false; // 4xx
        if (statusIdx == 4 && (code < 500 || code >= 600)) return false; // 5xx

        // 5. Search text
        String query = searchField.getText().trim().toLowerCase();
        if (!query.isEmpty()) {
            boolean urlMatch = entry.getUrl().toLowerCase().contains(query);
            boolean methodMatch = entry.getMethodName().toLowerCase().contains(query);
            boolean serviceMatch = entry.getService().toLowerCase().contains(query);
            boolean httpMethodMatch = entry.getHttpMethod().toLowerCase().contains(query);

            if (!urlMatch && !methodMatch && !serviceMatch && !httpMethodMatch) {
                return false;
            }
        }

        return true;
    }

    private void updateCounterLabel() {
        int showing = tableModel.getRowCount();
        int total = masterEntries.size();
        long gwtCount = masterEntries.stream().filter(GwtProxyHistoryEntry::isGwtRpc).count();
        counterLabel.setText(String.format("Showing %d / %d requests (%d GWT-RPC)", showing, total, gwtCount));
    }

    private void resetFilters() {
        searchField.setText("");
        methodFilterCombo.setSelectedIndex(0);
        serviceFilterCombo.setSelectedIndex(0);
        statusFilterCombo.setSelectedIndex(0);
        onlyGwtBox.setSelected(true);
        refreshFilteredViews();
    }

    private void clearAllHistory() {
        synchronized (masterEntries) {
            masterEntries.clear();
        }
        tableModel.clear();
        clearEditorViews();
        updateFilterOptions();
        updateCounterLabel();
    }
}
