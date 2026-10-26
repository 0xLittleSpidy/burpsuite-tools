// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.littlespidy.apiinspector.model.SessionStore_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dedicated tab providing an interactive request and response viewer for discovered API endpoints.
 * Displays all requests in the top pane with multi-select collection, method, and auth filters.
 * Features an editable HTTP request editor, live 'Run' and 'Run All' buttons, auto-saving of
 * parameter and body modifications, and real-time execution tracking.
 */
public class RequestResponseViewerTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final List<ImportedCollection_littlespidy> collections = new ArrayList<>();
    private final List<EndpointItem> endpointItems = new ArrayList<>();
    private final Map<String, HttpResponse> cachedResponses = new ConcurrentHashMap<>();

    private CollectionFilterDropDown_littlespidy collectionFilterDropDown;
    private MethodFilterDropDown_littlespidy methodFilterDropDown;
    private AuthFilterDropDown_littlespidy authFilterDropDown;
    private JTextField searchField;
    private JLabel requestCountLabel;
    private JButton runBtn;
    private JButton runAllBtn;
    private JButton stopBtn;
    private JButton resetBtn;
    private JProgressBar progressBar;
    private JLabel runStatusLabel;
    private JButton sessionStoreBtn;
    private JLabel sessionStoreStatusLabel;
    private SessionStore_littlespidy sessionStore = new SessionStore_littlespidy();

    private RequestTableModel tableModel;
    private JTable requestsTable;
    private TableRowSorter<RequestTableModel> tableSorter;

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JLabel responseInfoLabel;

    private EndpointItem currentlyLoadedItem = null;
    private boolean isUpdatingEditor = false;
    private final AtomicBoolean cancelRunAll = new AtomicBoolean(false);
    private ExecutorService runAllExecutor = null;

    public interface SendToVersionFinderCallback {
        void onSendToVersionFinder(ImportedCollection_littlespidy collection, DiscoveredEndpoint_littlespidy endpoint);
    }
    private SendToVersionFinderCallback onSendToVersionFinderListener;

    public void setOnSendToVersionFinderListener(SendToVersionFinderCallback listener) {
        this.onSendToVersionFinderListener = listener;
    }

    public RequestResponseViewerTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    private void initComponents() {
        // --- 1. Top Controls Bar ---
        JPanel topContainer = new JPanel(new BorderLayout(8, 4));
        topContainer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(2, 4, 6, 4)
        ));

        JPanel leftFilters = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        collectionFilterDropDown = new CollectionFilterDropDown_littlespidy();
        collectionFilterDropDown.addFilterChangeListener(this::applyFilters);
        leftFilters.add(collectionFilterDropDown);

        methodFilterDropDown = new MethodFilterDropDown_littlespidy();
        methodFilterDropDown.addFilterChangeListener(this::applyFilters);
        leftFilters.add(methodFilterDropDown);

        authFilterDropDown = new AuthFilterDropDown_littlespidy();
        authFilterDropDown.addFilterChangeListener(this::applyFilters);
        leftFilters.add(authFilterDropDown);

        leftFilters.add(new JLabel("Search:"));
        searchField = new JTextField(16);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });
        leftFilters.add(searchField);

        JButton clearFilterBtn = new JButton("Clear Filters");
        clearFilterBtn.addActionListener(e -> {
            collectionFilterDropDown.selectAll(true);
            methodFilterDropDown.selectAll(true);
            authFilterDropDown.selectAll(true);
            searchField.setText("");
            applyFilters();
        });
        leftFilters.add(clearFilterBtn);

        topContainer.add(leftFilters, BorderLayout.WEST);

        JPanel rightActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));

        sessionStoreStatusLabel = new JLabel(sessionStore.getStatusSummary());
        sessionStoreStatusLabel.setFont(sessionStoreStatusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        sessionStoreStatusLabel.setForeground(new Color(0, 100, 30));
        rightActions.add(sessionStoreStatusLabel);

        sessionStoreBtn = new JButton("Session Store");
        sessionStoreBtn.setToolTipText("Configure session authentication credentials, tokens, and custom headers");
        sessionStoreBtn.addActionListener(e -> {
            SessionStoreDialog_littlespidy dialog = new SessionStoreDialog_littlespidy(
                    SwingUtilities.getWindowAncestor(this),
                    sessionStore,
                    () -> {
                        sessionStoreStatusLabel.setText(sessionStore.getStatusSummary());
                        onEndpointRowSelected();
                    }
            );
            dialog.setVisible(true);
        });
        rightActions.add(sessionStoreBtn);

        runBtn = new JButton("Run");
        runBtn.setToolTipText("Run the currently selected request (with any user edits) against the target server");
        runBtn.addActionListener(e -> onRunRequest());
        rightActions.add(runBtn);

        runAllBtn = new JButton("Run All");
        runAllBtn.setToolTipText("Run all filtered requests sequentially in the background");
        runAllBtn.addActionListener(e -> onRunAll());
        rightActions.add(runAllBtn);

        stopBtn = new JButton("Stop");
        stopBtn.setToolTipText("Cancel active 'Run All' execution");
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> onStopRunAll());
        rightActions.add(stopBtn);

        resetBtn = new JButton("Reset");
        resetBtn.setToolTipText("Reset request edits for the selected endpoint back to original imported spec template");
        resetBtn.addActionListener(e -> onResetRequest());
        rightActions.add(resetBtn);

        progressBar = new JProgressBar(0, 100);
        progressBar.setPreferredSize(new Dimension(100, 20));
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        rightActions.add(progressBar);

        runStatusLabel = new JLabel("");
        runStatusLabel.setFont(runStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        rightActions.add(runStatusLabel);

        requestCountLabel = new JLabel("Requests: 0");
        rightActions.add(requestCountLabel);
        topContainer.add(rightActions, BorderLayout.EAST);

        add(topContainer, BorderLayout.NORTH);

        // --- 2. Main Vertical Split: Top Requests Table, Bottom Side-by-Side Viewer ---
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.48);
        mainSplit.setContinuousLayout(true);

        // Top Pane: All Requests Table
        JPanel topTablePanel = new JPanel(new BorderLayout(4, 4));
        topTablePanel.setBorder(new TitledBorder("Discovered API Requests"));

        tableModel = new RequestTableModel();
        requestsTable = new JTable(tableModel);
        tableSorter = new TableRowSorter<>(tableModel);
        requestsTable.setRowSorter(tableSorter);
        requestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onEndpointRowSelected();
            }
        });

        // Set column widths and cell renderers
        initTableRenderers();

        requestsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }

            private void showContextMenu(MouseEvent e) {
                int row = requestsTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    if (!requestsTable.isRowSelected(row)) {
                        requestsTable.setRowSelectionInterval(row, row);
                    }
                    int modelRow = requestsTable.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < endpointItems.size()) {
                        EndpointItem item = endpointItems.get(modelRow);
                        JPopupMenu menu = new JPopupMenu();

                        JMenuItem sendToVF = new JMenuItem("Send to ResAPI Version Finder");
                        sendToVF.addActionListener(ev -> {
                            if (onSendToVersionFinderListener != null) {
                                onSendToVersionFinderListener.onSendToVersionFinder(item.collection, item.endpoint);
                            }
                        });
                        menu.add(sendToVF);

                        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
                        sendToRepeater.addActionListener(ev -> {
                            try {
                                String targetBaseUrl = (item.collection.getTargetBaseUrl() != null && !item.collection.getTargetBaseUrl().isBlank())
                                        ? item.collection.getTargetBaseUrl() : "https://localhost";
                                HttpRequest req = AuthTestEngine_littlespidy.buildRequest(targetBaseUrl, item.endpoint, null, false);
                                if (sessionStore != null && sessionStore.appliesTo(item.endpoint)) {
                                    req = sessionStore.applyToRequest(req, item.endpoint);
                                }
                                if (api != null && api.repeater() != null) {
                                    api.repeater().sendToRepeater(req, item.endpoint.getMethod() + " " + item.endpoint.getPath());
                                }
                            } catch (Exception ignored) {}
                        });
                        menu.add(sendToRepeater);

                        menu.show(requestsTable, e.getX(), e.getY());
                    }
                }
            }
        });

        topTablePanel.add(new JScrollPane(requestsTable), BorderLayout.CENTER);
        mainSplit.setTopComponent(topTablePanel);

        // Bottom Pane: Request & Response Arranged Horizontally
        JPanel bottomViewerPanel = new JPanel(new BorderLayout(4, 4));
        bottomViewerPanel.setBorder(new EmptyBorder(0, 0, 0, 0));

        JSplitPane horizontalMessageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        horizontalMessageSplit.setResizeWeight(0.50);
        horizontalMessageSplit.setContinuousLayout(true);

        // Left Component: Request Viewer (Editable)
        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBorder(new TitledBorder("HTTP Request (Editable)"));
        if (api != null && api.userInterface() != null) {
            // Omit EditorOptions.READ_ONLY so the request editor is fully editable by user
            requestEditor = api.userInterface().createHttpRequestEditor();
            reqPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            reqPanel.add(new JLabel("Request editor unavailable in mock environment.", JLabel.CENTER), BorderLayout.CENTER);
        }
        horizontalMessageSplit.setLeftComponent(reqPanel);

        // Right Component: Response Viewer
        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBorder(new TitledBorder("HTTP Response"));
        responseInfoLabel = new JLabel("Status: - | Length: 0 B");
        responseInfoLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        respPanel.add(responseInfoLabel, BorderLayout.NORTH);

        if (api != null && api.userInterface() != null) {
            responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
            respPanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            respPanel.add(new JLabel("Response editor unavailable in mock environment.", JLabel.CENTER), BorderLayout.CENTER);
        }
        horizontalMessageSplit.setRightComponent(respPanel);

        bottomViewerPanel.add(horizontalMessageSplit, BorderLayout.CENTER);
        mainSplit.setBottomComponent(bottomViewerPanel);

        add(mainSplit, BorderLayout.CENTER);
    }

    private void initTableRenderers() {
        if (requestsTable.getColumnModel().getColumnCount() >= 9) {
            requestsTable.getColumnModel().getColumn(0).setPreferredWidth(110); // Collection
            requestsTable.getColumnModel().getColumn(1).setPreferredWidth(60);  // Method
            requestsTable.getColumnModel().getColumn(2).setPreferredWidth(210); // Path
            requestsTable.getColumnModel().getColumn(3).setPreferredWidth(60);  // Status
            requestsTable.getColumnModel().getColumn(4).setPreferredWidth(55);  // Edited
            requestsTable.getColumnModel().getColumn(5).setPreferredWidth(170); // Summary
            requestsTable.getColumnModel().getColumn(6).setPreferredWidth(85);  // Requires Auth
            requestsTable.getColumnModel().getColumn(7).setPreferredWidth(110); // Content Type
            requestsTable.getColumnModel().getColumn(8).setPreferredWidth(170); // Parameters
        }

        // Status column renderer
        requestsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (isSelected) {
                    return c;
                }
                c.setForeground(table.getForeground());
                c.setFont(table.getFont());

                if (col == 3 && value != null) { // Status
                    String statusStr = value.toString().trim();
                    try {
                        int code = Integer.parseInt(statusStr);
                        if (code >= 200 && code < 300) {
                            c.setForeground(new Color(0, 130, 0)); // Green
                        } else if (code >= 300 && code < 400) {
                            c.setForeground(new Color(0, 80, 200)); // Blue
                        } else if (code >= 400 && code < 500) {
                            c.setForeground(new Color(200, 100, 0)); // Amber / Orange
                        } else if (code >= 500) {
                            c.setForeground(new Color(180, 0, 0)); // Red
                        }
                    } catch (NumberFormatException ignored) {
                        c.setForeground(Color.GRAY);
                    }
                } else if (col == 4 && value != null) { // Edited
                    if ("Yes".equals(value.toString())) {
                        c.setForeground(new Color(0, 90, 180));
                        c.setFont(c.getFont().deriveFont(Font.BOLD));
                    } else {
                        c.setForeground(Color.GRAY);
                    }
                }
                return c;
            }
        });
    }

    public synchronized void updateCollections(List<ImportedCollection_littlespidy> cols) {
        if (currentlyLoadedItem != null) {
            saveEditorChangesToEndpoint(currentlyLoadedItem);
        }
        currentlyLoadedItem = null;

        collections.clear();
        endpointItems.clear();
        if (cols != null) {
            collections.addAll(cols);
            for (ImportedCollection_littlespidy c : cols) {
                for (DiscoveredEndpoint_littlespidy ep : c.getEndpoints()) {
                    endpointItems.add(new EndpointItem(c, ep));
                    methodFilterDropDown.registerMethod(ep.getMethod());
                }
            }
        }

        collectionFilterDropDown.updateCollections(collections);
        tableModel.fireTableDataChanged();
        applyFilters();
    }

    private void applyFilters() {
        if (tableSorter == null) return;

        tableSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends RequestTableModel, ? extends Integer> entry) {
                int modelRow = entry.getIdentifier();
                if (modelRow < 0 || modelRow >= endpointItems.size()) {
                    return false;
                }
                EndpointItem item = endpointItems.get(modelRow);

                // Collection filter
                if (!collectionFilterDropDown.isCollectionSelected(item.collection.getId())) {
                    return false;
                }

                // Method filter
                if (!methodFilterDropDown.isMethodSelected(item.endpoint.getMethod())) {
                    return false;
                }

                // Authentication requirement filter
                if (authFilterDropDown != null && !authFilterDropDown.isAuthOptionSelected(item.endpoint.isRequiresAuth())) {
                    return false;
                }

                // Search query
                String query = searchField.getText().trim();
                if (!query.isEmpty()) {
                    String q = query.toLowerCase(Locale.ROOT);
                    boolean match = item.endpoint.getPath().toLowerCase(Locale.ROOT).contains(q)
                            || item.endpoint.getMethod().toLowerCase(Locale.ROOT).contains(q)
                            || item.endpoint.getSummary().toLowerCase(Locale.ROOT).contains(q)
                            || item.collection.getName().toLowerCase(Locale.ROOT).contains(q);
                    if (!match) {
                        return false;
                    }
                }

                return true;
            }
        });

        int rowCount = requestsTable.getRowCount();
        requestCountLabel.setText("Requests: " + rowCount + " of " + endpointItems.size());

        if (rowCount > 0 && requestsTable.getSelectedRow() < 0) {
            requestsTable.setRowSelectionInterval(0, 0);
        }
    }

    private void saveEditorChangesToEndpoint(EndpointItem item) {
        if (item == null || requestEditor == null || isUpdatingEditor) return;
        try {
            HttpRequest edReq = requestEditor.getRequest();
            if (edReq == null || edReq.toByteArray() == null || edReq.toByteArray().length() == 0) {
                return;
            }
            byte[] bytes = edReq.toByteArray().getBytes();
            String currentText = new String(bytes, StandardCharsets.UTF_8);

            String targetBaseUrl = (item.collection.getTargetBaseUrl() != null && !item.collection.getTargetBaseUrl().isBlank())
                    ? item.collection.getTargetBaseUrl() : "https://localhost";
            HttpRequest defReq = AuthTestEngine_littlespidy.buildDefaultRequest(targetBaseUrl, item.endpoint);
            if (sessionStore != null && sessionStore.appliesTo(item.endpoint)) {
                defReq = sessionStore.applyToRequest(defReq, item.endpoint);
            }
            String defaultText = (defReq != null && defReq.toByteArray() != null)
                    ? new String(defReq.toByteArray().getBytes(), StandardCharsets.UTF_8) : "";

            if (!currentText.equals(defaultText)) {
                item.endpoint.setCustomRawRequest(currentText);
            } else {
                item.endpoint.resetCustomRequest();
            }
        } catch (Exception ignored) {}
    }

    private void onEndpointRowSelected() {
        if (isUpdatingEditor) return;

        // Auto-save any changes from previous selection
        if (currentlyLoadedItem != null) {
            saveEditorChangesToEndpoint(currentlyLoadedItem);
        }

        int row = requestsTable.getSelectedRow();
        if (row < 0 || row >= requestsTable.getRowCount()) {
            currentlyLoadedItem = null;
            clearEditors();
            return;
        }

        int modelRow = requestsTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= endpointItems.size()) {
            currentlyLoadedItem = null;
            clearEditors();
            return;
        }

        EndpointItem item = endpointItems.get(modelRow);
        currentlyLoadedItem = item;
        String targetBaseUrl = (item.collection.getTargetBaseUrl() != null && !item.collection.getTargetBaseUrl().isBlank())
                ? item.collection.getTargetBaseUrl()
                : "https://localhost";

        try {
            HttpRequest req = AuthTestEngine_littlespidy.buildRequest(targetBaseUrl, item.endpoint, null, false);
            if (sessionStore != null && sessionStore.appliesTo(item.endpoint)) {
                req = sessionStore.applyToRequest(req, item.endpoint);
            }

            isUpdatingEditor = true;
            try {
                if (requestEditor != null) {
                    requestEditor.setRequest(req);
                }
            } finally {
                isUpdatingEditor = false;
            }

            // Check cached response
            String key = item.collection.getId() + ":" + item.endpoint.getMethod() + ":" + item.endpoint.getPath();
            HttpResponse resp = cachedResponses.get(key);
            if (resp != null) {
                if (responseEditor != null) {
                    responseEditor.setResponse(resp);
                }
                responseInfoLabel.setText("Status: " + resp.statusCode() + " | Length: " + (resp.body() != null ? resp.body().length() : 0) + " B");
            } else {
                if (responseEditor != null) {
                    responseEditor.setResponse(null);
                }
                responseInfoLabel.setText("Status: [Not Run] | Click 'Run' to execute request");
            }
        } catch (Exception ex) {
            if (requestEditor != null) {
                requestEditor.setRequest(null);
            }
            responseInfoLabel.setText("Error constructing request: " + ex.getMessage());
        }
    }

    private void onRunRequest() {
        if (currentlyLoadedItem == null) {
            JOptionPane.showMessageDialog(this, "Please select a request from the table to run.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Persist edits before sending
        saveEditorChangesToEndpoint(currentlyLoadedItem);
        tableModel.fireTableDataChanged();

        HttpRequest reqToSend = null;
        if (requestEditor != null) {
            reqToSend = requestEditor.getRequest();
        }
        if (reqToSend == null) {
            String targetBaseUrl = (currentlyLoadedItem.collection.getTargetBaseUrl() != null && !currentlyLoadedItem.collection.getTargetBaseUrl().isBlank())
                    ? currentlyLoadedItem.collection.getTargetBaseUrl() : "https://localhost";
            reqToSend = AuthTestEngine_littlespidy.buildRequest(targetBaseUrl, currentlyLoadedItem.endpoint, null, false);
            if (sessionStore != null && sessionStore.appliesTo(currentlyLoadedItem.endpoint)) {
                reqToSend = sessionStore.applyToRequest(reqToSend, currentlyLoadedItem.endpoint);
            }
        }

        final HttpRequest finalReq = reqToSend;
        final EndpointItem item = currentlyLoadedItem;

        runBtn.setEnabled(false);
        runAllBtn.setEnabled(false);
        responseInfoLabel.setText("Running request...");

        Thread t = new Thread(() -> {
            try {
                if (api != null && api.http() != null) {
                    HttpRequestResponse resp = api.http().sendRequest(finalReq);
                    if (resp != null && resp.hasResponse()) {
                        HttpResponse httpResp = resp.response();
                        String key = item.collection.getId() + ":" + item.endpoint.getMethod() + ":" + item.endpoint.getPath();
                        cachedResponses.put(key, httpResp);

                        SwingUtilities.invokeLater(() -> {
                            if (responseEditor != null) {
                                responseEditor.setResponse(httpResp);
                            }
                            responseInfoLabel.setText("Status: " + httpResp.statusCode() + " | Length: " + (httpResp.body() != null ? httpResp.body().length() : 0) + " B");
                            runBtn.setEnabled(true);
                            runAllBtn.setEnabled(true);
                            tableModel.fireTableDataChanged();
                        });
                        return;
                    }
                }

                SwingUtilities.invokeLater(() -> {
                    responseInfoLabel.setText("No response received (check target URL or network connectivity)");
                    runBtn.setEnabled(true);
                    runAllBtn.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    responseInfoLabel.setText("Run failed: " + ex.getMessage());
                    runBtn.setEnabled(true);
                    runAllBtn.setEnabled(true);
                });
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void onRunAll() {
        if (currentlyLoadedItem != null) {
            saveEditorChangesToEndpoint(currentlyLoadedItem);
        }

        List<EndpointItem> itemsToRun = new ArrayList<>();
        for (int r = 0; r < requestsTable.getRowCount(); r++) {
            int modelRow = requestsTable.convertRowIndexToModel(r);
            if (modelRow >= 0 && modelRow < endpointItems.size()) {
                itemsToRun.add(endpointItems.get(modelRow));
            }
        }

        if (itemsToRun.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No requests match the current filters.", "Run All", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        cancelRunAll.set(false);
        runBtn.setEnabled(false);
        runAllBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        progressBar.setVisible(true);
        progressBar.setMinimum(0);
        progressBar.setMaximum(itemsToRun.size());
        progressBar.setValue(0);
        runStatusLabel.setText("Running: 0 / " + itemsToRun.size());

        Thread coordinator = new Thread(() -> {
            int total = itemsToRun.size();
            AtomicInteger completed = new AtomicInteger(0);
            int threads = Math.min(5, Math.max(1, total));
            runAllExecutor = Executors.newFixedThreadPool(threads);

            for (EndpointItem item : itemsToRun) {
                if (cancelRunAll.get()) break;

                runAllExecutor.submit(() -> {
                    if (cancelRunAll.get()) return;

                    try {
                        String targetBaseUrl = (item.collection.getTargetBaseUrl() != null && !item.collection.getTargetBaseUrl().isBlank())
                                ? item.collection.getTargetBaseUrl() : "https://localhost";
                        HttpRequest req = AuthTestEngine_littlespidy.buildRequest(targetBaseUrl, item.endpoint, null, false);
                        if (sessionStore != null && sessionStore.appliesTo(item.endpoint)) {
                            req = sessionStore.applyToRequest(req, item.endpoint);
                        }

                        if (api != null && api.http() != null) {
                            HttpRequestResponse resp = api.http().sendRequest(req);
                            if (resp != null && resp.hasResponse()) {
                                HttpResponse httpResp = resp.response();
                                String key = item.collection.getId() + ":" + item.endpoint.getMethod() + ":" + item.endpoint.getPath();
                                cachedResponses.put(key, httpResp);
                            }
                        }
                    } catch (Exception ignored) {
                    } finally {
                        int done = completed.incrementAndGet();
                        SwingUtilities.invokeLater(() -> {
                            progressBar.setValue(done);
                            runStatusLabel.setText("Running: " + done + " / " + total);
                            tableModel.fireTableDataChanged();
                        });
                    }
                });
            }

            runAllExecutor.shutdown();
            try {
                runAllExecutor.awaitTermination(30, TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            boolean stopped = cancelRunAll.get();
            SwingUtilities.invokeLater(() -> {
                runBtn.setEnabled(true);
                runAllBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                progressBar.setVisible(false);
                runStatusLabel.setText(stopped ? "Stopped (" + completed.get() + " / " + total + ")." : "Finished (" + completed.get() + " / " + total + " requests).");
                tableModel.fireTableDataChanged();
                onEndpointRowSelected();
            });
        });
        coordinator.setDaemon(true);
        coordinator.start();
    }

    private void onStopRunAll() {
        cancelRunAll.set(true);
        if (runAllExecutor != null && !runAllExecutor.isShutdown()) {
            runAllExecutor.shutdownNow();
        }
        stopBtn.setEnabled(false);
        runStatusLabel.setText("Stopping...");
    }

    private void onResetRequest() {
        if (currentlyLoadedItem == null) return;

        currentlyLoadedItem.endpoint.resetCustomRequest();
        String targetBaseUrl = (currentlyLoadedItem.collection.getTargetBaseUrl() != null && !currentlyLoadedItem.collection.getTargetBaseUrl().isBlank())
                ? currentlyLoadedItem.collection.getTargetBaseUrl() : "https://localhost";
        HttpRequest defReq = AuthTestEngine_littlespidy.buildDefaultRequest(targetBaseUrl, currentlyLoadedItem.endpoint);
        if (sessionStore != null && sessionStore.appliesTo(currentlyLoadedItem.endpoint)) {
            defReq = sessionStore.applyToRequest(defReq, currentlyLoadedItem.endpoint);
        }

        isUpdatingEditor = true;
        try {
            if (requestEditor != null) {
                requestEditor.setRequest(defReq);
            }
        } finally {
            isUpdatingEditor = false;
        }

        tableModel.fireTableDataChanged();
        responseInfoLabel.setText("Request reset to original spec template.");
    }

    private void clearEditors() {
        if (requestEditor != null) requestEditor.setRequest(null);
        if (responseEditor != null) responseEditor.setResponse(null);
        responseInfoLabel.setText("Status: - | Length: 0 B");
    }

    public SessionStore_littlespidy getSessionStore() {
        return sessionStore;
    }

    public void setSessionStore(SessionStore_littlespidy store) {
        this.sessionStore = store != null ? store : new SessionStore_littlespidy();
        if (sessionStoreStatusLabel != null) {
            sessionStoreStatusLabel.setText(this.sessionStore.getStatusSummary());
        }
        onEndpointRowSelected();
    }

    public boolean selectAndDisplayEndpoint(DiscoveredEndpoint_littlespidy targetEp) {
        if (targetEp == null || endpointItems.isEmpty()) {
            return false;
        }

        int targetModelIndex = -1;
        for (int i = 0; i < endpointItems.size(); i++) {
            EndpointItem item = endpointItems.get(i);
            if (item.endpoint == targetEp ||
                (targetEp.getId() != null && targetEp.getId().equals(item.endpoint.getId())) ||
                (targetEp.getMethod() != null && targetEp.getMethod().equalsIgnoreCase(item.endpoint.getMethod()) &&
                 targetEp.getPath() != null && targetEp.getPath().equals(item.endpoint.getPath()))) {
                targetModelIndex = i;
                break;
            }
        }

        if (targetModelIndex == -1) {
            return false;
        }

        int viewRow = requestsTable.convertRowIndexToView(targetModelIndex);
        if (viewRow == -1) {
            collectionFilterDropDown.selectAll(true);
            methodFilterDropDown.selectAll(true);
            if (authFilterDropDown != null) {
                authFilterDropDown.selectAll(true);
            }
            searchField.setText("");
            applyFilters();
            viewRow = requestsTable.convertRowIndexToView(targetModelIndex);
        }

        if (viewRow >= 0 && viewRow < requestsTable.getRowCount()) {
            requestsTable.setRowSelectionInterval(viewRow, viewRow);
            Rectangle rect = requestsTable.getCellRect(viewRow, 0, true);
            requestsTable.scrollRectToVisible(rect);
            onEndpointRowSelected();
            return true;
        }

        return false;
    }

    public AuthFilterDropDown_littlespidy getAuthFilterDropDown() {
        return authFilterDropDown;
    }

    public RequestTableModel getTableModel() {
        return tableModel;
    }

    public List<EndpointItem> getEndpointItems() {
        return endpointItems;
    }

    public static class EndpointItem {
        public final ImportedCollection_littlespidy collection;
        public final DiscoveredEndpoint_littlespidy endpoint;

        public EndpointItem(ImportedCollection_littlespidy collection, DiscoveredEndpoint_littlespidy endpoint) {
            this.collection = collection;
            this.endpoint = endpoint;
        }
    }

    public class RequestTableModel extends AbstractTableModel {
        private final String[] columns = {"Collection", "Method", "Path", "Status", "Edited", "Summary", "Requires Auth", "Content Type", "Parameters"};

        @Override public int getRowCount() { return endpointItems.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= endpointItems.size()) return "";
            EndpointItem it = endpointItems.get(row);
            switch (col) {
                case 0: return it.collection.getName();
                case 1: return it.endpoint.getMethod();
                case 2: return it.endpoint.getPath();
                case 3: {
                    String key = it.collection.getId() + ":" + it.endpoint.getMethod() + ":" + it.endpoint.getPath();
                    HttpResponse resp = cachedResponses.get(key);
                    return resp != null ? String.valueOf(resp.statusCode()) : "-";
                }
                case 4: return it.endpoint.hasCustomRequest() ? "Yes" : "-";
                case 5: return it.endpoint.getSummary();
                case 6: return it.endpoint.isRequiresAuth() ? "Yes" : "No";
                case 7: return it.endpoint.getContentType();
                case 8: return it.endpoint.getParametersSummary();
                default: return "";
            }
        }
    }
}
