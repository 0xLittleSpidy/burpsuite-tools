// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Dedicated suite tab for Hidden API Storage.
 * Stores, catalogs, and inspects API endpoints discovered during Endpoint Discovery,
 * JS Analysis, REST API Version Probing, or ingested from Burp tools (Proxy, Repeater, Logger, Target).
 * Features double-click dropdown Source editing and parallel side-by-side Request/Response viewers.
 */
public class HiddenAPIStorageTab_littlespidy extends JPanel {

    public static final String[] SOURCE_OPTIONS = {
            "Endpoint Discovery",
            "JS Analysis",
            "Version Finder",
            "Proxy History",
            "Repeater",
            "Target Site Map",
            "Logger",
            "Manual Entry",
            "Other Tool"
    };

    private final MontoyaApi api;
    private final HiddenEndpointsTableModel_littlespidy tableModel;
    private final JTable endpointsTable;
    private final TableRowSorter<HiddenEndpointsTableModel_littlespidy> tableSorter;

    private JTextField searchField;
    private JComboBox<String> sourceFilterCombo;
    private JComboBox<String> methodFilterCombo;
    private JComboBox<String> statusFilterCombo;

    private JLabel metricsLabel;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JLabel requestMetaLabel;
    private JLabel responseMetaLabel;

    private Runnable onStateChangedCallback;

    public HiddenAPIStorageTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(4, 4));
        this.api = api;
        this.tableModel = new HiddenEndpointsTableModel_littlespidy();
        this.endpointsTable = new JTable(tableModel);
        this.tableSorter = new TableRowSorter<>(tableModel);

        setBorder(new EmptyBorder(6, 6, 6, 6));

        // Connect table model state changes to notify persistence
        this.tableModel.setOnStateChanged(() -> {
            updateMetrics();
            notifyStateChanged();
        });

        // 1. Build Top Filter & Action Bar
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.add(buildToolbarPanel());
        topContainer.add(Box.createVerticalStrut(4));
        topContainer.add(buildMetricsBar());
        add(topContainer, BorderLayout.NORTH);

        // 2. Build Center Component: Split Pane (Table on top, Parallel Viewers on bottom)
        endpointsTable.setRowSorter(tableSorter);
        endpointsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        endpointsTable.setRowHeight(24);

        // Configure Source column (Index 1) with dropdown JComboBox cell editor
        JComboBox<String> sourceComboEditor = new JComboBox<>(SOURCE_OPTIONS);
        endpointsTable.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(sourceComboEditor));

        // Custom Cell Renderers for Method and Status
        setupTableRenderers();

        // Listen for row selections to update parallel Request/Response viewers
        endpointsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateSelectedEndpointView();
            }
        });

        // Context Menu on table rows
        setupTableContextMenu();

        JScrollPane tableScroll = new JScrollPane(endpointsTable);
        tableScroll.setPreferredSize(new Dimension(800, 260));

        JPanel bottomParallelViewer = buildParallelViewerPanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomParallelViewer);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(260);

        add(splitPane, BorderLayout.CENTER);
        updateMetrics();
    }

    public void setOnStateChangedCallback(Runnable callback) {
        this.onStateChangedCallback = callback;
    }

    private void notifyStateChanged() {
        if (onStateChangedCallback != null) {
            onStateChangedCallback.run();
        }
    }

    private JPanel buildToolbarPanel() {
        JPanel toolbar = new JPanel(new BorderLayout(8, 4));
        toolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(4, 6, 6, 6)
        ));

        // Left Filter Controls
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        filterPanel.add(new JLabel("Filter:"));

        searchField = new JTextField(18);
        searchField.setToolTipText("Search URL, path, parameters, source, notes");
        searchField.getDocument().addDocumentListener(new SimpleDocumentListener(this::applyFilters));
        filterPanel.add(searchField);

        filterPanel.add(new JLabel("Source:"));
        sourceFilterCombo = new JComboBox<>(new String[]{
                "All Sources",
                "Endpoint Discovery",
                "JS Analysis",
                "Version Finder",
                "Proxy History",
                "Repeater",
                "Target Site Map",
                "Logger",
                "Manual Entry",
                "Other Tool"
        });
        sourceFilterCombo.addActionListener(e -> applyFilters());
        filterPanel.add(sourceFilterCombo);

        filterPanel.add(new JLabel("Method:"));
        methodFilterCombo = new JComboBox<>(new String[]{"All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"});
        methodFilterCombo.addActionListener(e -> applyFilters());
        filterPanel.add(methodFilterCombo);

        filterPanel.add(new JLabel("Status:"));
        statusFilterCombo = new JComboBox<>(new String[]{"All", "2xx Success", "3xx Redirect", "4xx Client Error", "5xx Server Error"});
        statusFilterCombo.addActionListener(e -> applyFilters());
        filterPanel.add(statusFilterCombo);

        toolbar.add(filterPanel, BorderLayout.CENTER);

        // Right Action Buttons
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));

        JButton addBtn = new JButton("+ Add Endpoint");
        addBtn.setFont(addBtn.getFont().deriveFont(Font.BOLD));
        addBtn.setToolTipText("Manually enter an API endpoint into storage");
        addBtn.addActionListener(e -> {
            AddHiddenEndpointDialog_littlespidy dialog = new AddHiddenEndpointDialog_littlespidy(
                    SwingUtilities.getWindowAncestor(this),
                    this::addEndpoint
            );
            dialog.setVisible(true);
        });
        actionPanel.add(addBtn);

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.setToolTipText("Export all stored hidden endpoints to CSV");
        exportBtn.addActionListener(e -> exportCsv());
        actionPanel.add(exportBtn);

        JButton deleteBtn = new JButton("Delete Selected");
        deleteBtn.setToolTipText("Delete the currently selected endpoint from storage");
        deleteBtn.addActionListener(e -> deleteSelected());
        actionPanel.add(deleteBtn);

        JButton clearBtn = new JButton("Clear All");
        clearBtn.setToolTipText("Clear all stored hidden endpoints");
        clearBtn.addActionListener(e -> clearAll());
        actionPanel.add(clearBtn);

        toolbar.add(actionPanel, BorderLayout.EAST);
        return toolbar;
    }

    private JPanel buildMetricsBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        bar.setBackground(new Color(245, 245, 245));
        bar.setBorder(new EmptyBorder(2, 6, 2, 6));

        metricsLabel = new JLabel("Total: 0 Endpoints | Double-click Source cell to edit category dropdown");
        metricsLabel.setFont(metricsLabel.getFont().deriveFont(Font.PLAIN, 11f));
        bar.add(metricsLabel);
        return bar;
    }

    private JPanel buildParallelViewerPanel() {
        JPanel container = new JPanel(new BorderLayout(4, 4));
        container.setBorder(new EmptyBorder(4, 4, 4, 4));

        // Left: Request Viewer
        JPanel reqPanel = new JPanel(new BorderLayout(2, 2));
        reqPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Request Viewer", TitledBorder.LEFT, TitledBorder.TOP));
        requestMetaLabel = new JLabel("No request selected");
        requestMetaLabel.setFont(requestMetaLabel.getFont().deriveFont(Font.PLAIN, 11f));
        requestMetaLabel.setBorder(new EmptyBorder(2, 4, 2, 4));
        reqPanel.add(requestMetaLabel, BorderLayout.NORTH);

        if (api != null && api.userInterface() != null) {
            requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            reqPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            JTextArea fallback = new JTextArea("Request editor available inside Burp Suite.");
            fallback.setEditable(false);
            reqPanel.add(new JScrollPane(fallback), BorderLayout.CENTER);
        }

        // Right: Response Viewer
        JPanel respPanel = new JPanel(new BorderLayout(2, 2));
        respPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Response Viewer", TitledBorder.LEFT, TitledBorder.TOP));
        responseMetaLabel = new JLabel("No response selected");
        responseMetaLabel.setFont(responseMetaLabel.getFont().deriveFont(Font.PLAIN, 11f));
        responseMetaLabel.setBorder(new EmptyBorder(2, 4, 2, 4));
        respPanel.add(responseMetaLabel, BorderLayout.NORTH);

        if (api != null && api.userInterface() != null) {
            responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
            respPanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            JTextArea fallback = new JTextArea("Response editor available inside Burp Suite.");
            fallback.setEditable(false);
            respPanel.add(new JScrollPane(fallback), BorderLayout.CENTER);
        }

        // Side-by-side horizontal split pane (50% / 50%)
        JSplitPane parallelSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        parallelSplit.setResizeWeight(0.5);
        parallelSplit.setDividerLocation(450);

        container.add(parallelSplit, BorderLayout.CENTER);
        return container;
    }

    private void setupTableRenderers() {
        // Method cell renderer with bold text
        endpointsTable.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                l.setFont(l.getFont().deriveFont(Font.BOLD));
                l.setHorizontalAlignment(SwingConstants.CENTER);
                return l;
            }
        });

        // Status cell renderer
        endpointsTable.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                return l;
            }
        });
    }

    private void setupTableContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        repeaterItem.addActionListener(e -> sendSelectedToRepeater());
        menu.add(repeaterItem);

        JMenuItem intruderItem = new JMenuItem("Send to Intruder");
        intruderItem.addActionListener(e -> sendSelectedToIntruder());
        menu.add(intruderItem);

        menu.addSeparator();

        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        copyUrlItem.addActionListener(e -> {
            HiddenEndpoint_littlespidy ep = getSelectedEndpoint();
            if (ep != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(ep.getUrl()), null);
            }
        });
        menu.add(copyUrlItem);

        JMenuItem copyCurlItem = new JMenuItem("Copy as cURL");
        copyCurlItem.addActionListener(e -> {
            HiddenEndpoint_littlespidy ep = getSelectedEndpoint();
            if (ep != null) {
                String curl = "curl -i -X " + ep.getMethod() + " \"" + ep.getUrl() + "\"";
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(curl), null);
            }
        });
        menu.add(copyCurlItem);

        menu.addSeparator();

        JMenuItem deleteItem = new JMenuItem("Delete Endpoint");
        deleteItem.addActionListener(e -> deleteSelected());
        menu.add(deleteItem);

        endpointsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showMenu(e);
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showMenu(e);
                }
            }

            private void showMenu(MouseEvent e) {
                int row = endpointsTable.rowAtPoint(e.getPoint());
                if (row >= 0 && row < endpointsTable.getRowCount()) {
                    endpointsTable.setRowSelectionInterval(row, row);
                    menu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    private void updateSelectedEndpointView() {
        HiddenEndpoint_littlespidy ep = getSelectedEndpoint();
        if (ep == null) {
            requestMetaLabel.setText("No request selected");
            responseMetaLabel.setText("No response selected");
            if (requestEditor != null) requestEditor.setRequest(null);
            if (responseEditor != null) responseEditor.setResponse(null);
            return;
        }

        requestMetaLabel.setText(ep.getMethod() + " " + ep.getUrl());

        if (ep.getRawRequest() != null) {
            if (requestEditor != null) requestEditor.setRequest(ep.getRawRequest());
        } else {
            // Generate synthetic HttpRequest for inspection
            HttpRequest synthReq = createSyntheticRequest(ep);
            if (requestEditor != null) requestEditor.setRequest(synthReq);
        }

        if (ep.getRawResponse() != null) {
            int len = ep.getRawResponse().toByteArray().length();
            responseMetaLabel.setText("Status: " + ep.getStatusCode() + " | Length: " + len + " bytes");
            if (responseEditor != null) responseEditor.setResponse(ep.getRawResponse());
        } else {
            responseMetaLabel.setText(ep.getStatusCode() > 0 ? ("Status: " + ep.getStatusCode()) : "No response captured");
            if (responseEditor != null) responseEditor.setResponse(null);
        }
    }

    private HttpRequest createSyntheticRequest(HiddenEndpoint_littlespidy ep) {
        try {
            String fullUrl = ep.getUrl();
            if (fullUrl == null || fullUrl.isBlank()) fullUrl = "https://localhost" + ep.getPath();
            URI uri = URI.create(fullUrl);
            String host = uri.getHost() != null ? uri.getHost() : "localhost";
            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme()) || uri.getScheme() == null;
            int port = uri.getPort() != -1 ? uri.getPort() : (isHttps ? 443 : 80);
            String path = uri.getRawPath() != null && !uri.getRawPath().isEmpty() ? uri.getRawPath() : "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();

            HttpService service = HttpService.httpService(host, port, isHttps);
            String reqStr = ep.getMethod() + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            return HttpRequest.httpRequest(service, reqStr);
        } catch (Exception ex) {
            return null;
        }
    }

    public HiddenEndpoint_littlespidy getSelectedEndpoint() {
        int viewRow = endpointsTable.getSelectedRow();
        if (viewRow >= 0) {
            int modelRow = endpointsTable.convertRowIndexToModel(viewRow);
            return tableModel.getEndpointAt(modelRow);
        }
        return null;
    }

    public synchronized void addEndpoint(HiddenEndpoint_littlespidy endpoint) {
        if (endpoint == null) return;
        tableModel.addEndpoint(endpoint);
        endpointsTable.setRowSelectionInterval(0, 0);
        updateMetrics();
        notifyStateChanged();
    }

    /**
     * Ingestion entry point when an endpoint is sent from other Burp Suite tools
     * (Proxy HTTP history, Repeater, Logger, Target site map).
     */
    public synchronized void addEndpointFromBurpTool(HttpRequestResponse rr, String toolName) {
        if (rr == null || rr.request() == null) return;

        HttpRequest req = rr.request();
        HttpResponse resp = rr.hasResponse() ? rr.response() : null;

        String source = (toolName != null && !toolName.isBlank()) ? toolName : "Proxy History";
        String method = req.method() != null ? req.method() : "GET";
        String url = req.url() != null ? req.url() : "";
        String path = req.path() != null ? req.path() : "/";
        int status = resp != null ? resp.statusCode() : 0;
        String notes = "Ingested from " + source;

        HiddenEndpoint_littlespidy ep = new HiddenEndpoint_littlespidy(
                source,
                method,
                url,
                path,
                status,
                notes,
                req,
                resp
        );

        tableModel.addEndpoint(ep);
        endpointsTable.setRowSelectionInterval(0, 0);
        updateMetrics();
        notifyStateChanged();
    }

    public List<HiddenEndpoint_littlespidy> getAllEndpoints() {
        return tableModel.getAllEndpoints();
    }

    public void setEndpoints(List<HiddenEndpoint_littlespidy> list) {
        tableModel.setEndpoints(list);
        if (tableModel.getRowCount() > 0) {
            endpointsTable.setRowSelectionInterval(0, 0);
        }
        updateMetrics();
    }

    private void deleteSelected() {
        int viewRow = endpointsTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select an endpoint to delete.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = endpointsTable.convertRowIndexToModel(viewRow);
        tableModel.removeEndpoint(modelRow);
        updateMetrics();
        notifyStateChanged();
    }

    private void clearAll() {
        if (tableModel.getRowCount() == 0) return;
        int opt = JOptionPane.showConfirmDialog(this, "Are you sure you want to clear all " + tableModel.getRowCount() + " stored endpoints?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
        if (opt == JOptionPane.YES_OPTION) {
            tableModel.clear();
            updateMetrics();
            notifyStateChanged();
        }
    }

    private void sendSelectedToRepeater() {
        HiddenEndpoint_littlespidy ep = getSelectedEndpoint();
        if (ep == null) {
            JOptionPane.showMessageDialog(this, "Please select an endpoint first.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        HttpRequest req = ep.getRawRequest() != null ? ep.getRawRequest() : createSyntheticRequest(ep);
        if (req != null && api != null && api.repeater() != null) {
            api.repeater().sendToRepeater(req, "Hidden-" + ep.getMethod() + "-" + ep.getPath());
        }
    }

    private void sendSelectedToIntruder() {
        HiddenEndpoint_littlespidy ep = getSelectedEndpoint();
        if (ep == null) {
            JOptionPane.showMessageDialog(this, "Please select an endpoint first.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        HttpRequest req = ep.getRawRequest() != null ? ep.getRawRequest() : createSyntheticRequest(ep);
        if (req != null && api != null && api.intruder() != null) {
            api.intruder().sendToIntruder(req);
        }
    }

    private void exportCsv() {
        List<HiddenEndpoint_littlespidy> list = tableModel.getAllEndpoints();
        if (list.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No endpoints to export.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("hidden_api_endpoints.csv"));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write("ID,Source,Method,URL,Path,Parameters,StatusCode,DateAdded,Notes\n");
                for (HiddenEndpoint_littlespidy ep : list) {
                    writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\"\n",
                            escapeCsv(ep.getId()),
                            escapeCsv(ep.getSource()),
                            escapeCsv(ep.getMethod()),
                            escapeCsv(ep.getUrl()),
                            escapeCsv(ep.getPath()),
                            escapeCsv(ep.getParametersSummary()),
                            ep.getStatusCode(),
                            escapeCsv(ep.getFormattedDate()),
                            escapeCsv(ep.getNotes())
                    ));
                }
                JOptionPane.showMessageDialog(this, "Exported " + list.size() + " endpoints successfully to " + file.getName(), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to export CSV: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String escapeCsv(String val) {
        if (val == null) return "";
        return val.replace("\"", "\"\"");
    }

    private void applyFilters() {
        String query = searchField.getText().trim().toLowerCase();
        String selectedSource = (String) sourceFilterCombo.getSelectedItem();
        String selectedMethod = (String) methodFilterCombo.getSelectedItem();
        String selectedStatus = (String) statusFilterCombo.getSelectedItem();

        RowFilter<HiddenEndpointsTableModel_littlespidy, Integer> filter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends HiddenEndpointsTableModel_littlespidy, ? extends Integer> entry) {
                int modelRow = entry.getIdentifier();
                HiddenEndpoint_littlespidy ep = tableModel.getEndpointAt(modelRow);
                if (ep == null) return false;

                // Source filter
                if (selectedSource != null && !"All Sources".equals(selectedSource)) {
                    if (!selectedSource.equalsIgnoreCase(ep.getSource())) {
                        return false;
                    }
                }

                // Method filter
                if (selectedMethod != null && !"All".equals(selectedMethod)) {
                    if (!selectedMethod.equalsIgnoreCase(ep.getMethod())) {
                        return false;
                    }
                }

                // Status filter
                if (selectedStatus != null && !"All".equals(selectedStatus)) {
                    int sc = ep.getStatusCode();
                    if (selectedStatus.startsWith("2xx") && (sc < 200 || sc >= 300)) return false;
                    if (selectedStatus.startsWith("3xx") && (sc < 300 || sc >= 400)) return false;
                    if (selectedStatus.startsWith("4xx") && (sc < 400 || sc >= 500)) return false;
                    if (selectedStatus.startsWith("5xx") && (sc < 500 || sc >= 600)) return false;
                }

                // Text query filter across URL, path, params, notes, source, method
                if (!query.isEmpty()) {
                    boolean match = (ep.getUrl() != null && ep.getUrl().toLowerCase().contains(query))
                            || (ep.getPath() != null && ep.getPath().toLowerCase().contains(query))
                            || (ep.getMethod() != null && ep.getMethod().toLowerCase().contains(query))
                            || (ep.getSource() != null && ep.getSource().toLowerCase().contains(query))
                            || (ep.getParametersSummary() != null && ep.getParametersSummary().toLowerCase().contains(query))
                            || (ep.getNotes() != null && ep.getNotes().toLowerCase().contains(query));
                    if (!match) return false;
                }

                return true;
            }
        };

        tableSorter.setRowFilter(filter);
    }

    private void updateMetrics() {
        List<HiddenEndpoint_littlespidy> list = tableModel.getAllEndpoints();
        long discCount = list.stream().filter(e -> "Endpoint Discovery".equalsIgnoreCase(e.getSource())).count();
        long jsCount = list.stream().filter(e -> "JS Analysis".equalsIgnoreCase(e.getSource())).count();
        long vfCount = list.stream().filter(e -> "Version Finder".equalsIgnoreCase(e.getSource())).count();
        long proxyCount = list.stream().filter(e -> "Proxy History".equalsIgnoreCase(e.getSource()) || "Repeater".equalsIgnoreCase(e.getSource())).count();
        long manualCount = list.stream().filter(e -> "Manual Entry".equalsIgnoreCase(e.getSource())).count();

        metricsLabel.setText(String.format(
                "Total: %d Endpoints | Endpoint Discovery: %d | JS Analysis: %d | Version Finder: %d | Proxy/Repeater: %d | Manual: %d",
                list.size(), discCount, jsCount, vfCount, proxyCount, manualCount
        ));
    }

    public JTable getEndpointsTable() {
        return endpointsTable;
    }

    public HiddenEndpointsTableModel_littlespidy getTableModel() {
        return tableModel;
    }

    /**
     * Utility DocumentListener for real-time text filter updates.
     */
    private static class SimpleDocumentListener implements javax.swing.event.DocumentListener {
        private final Runnable onChange;

        public SimpleDocumentListener(Runnable onChange) {
            this.onChange = onChange;
        }

        @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { onChange.run(); }
        @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { onChange.run(); }
        @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { onChange.run(); }
    }
}
