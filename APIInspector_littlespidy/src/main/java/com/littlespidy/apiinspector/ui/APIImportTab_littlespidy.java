// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.littlespidy.apiinspector.parser.APIParserFactory_littlespidy;
import com.littlespidy.apiinspector.parser.ParseResult_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.List;

/**
 * Tab for importing, inspecting, and managing API definitions and collections
 * from local files or remote URLs.
 */
public class APIImportTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final List<ImportedCollection_littlespidy> collections = new ArrayList<>();
    private final List<AuthProfile_littlespidy> availableProfiles = new ArrayList<>();

    private CollectionTableModel collectionTableModel;
    private JTable collectionTable;
    private TableRowSorter<CollectionTableModel> collectionSorter;

    private EndpointTableModel endpointTableModel;
    private JTable endpointTable;
    private TableRowSorter<EndpointTableModel> endpointSorter;

    private JLabel collectionCountLabel;
    private JLabel endpointCountLabel;
    private JTextField endpointSearchField;
    private MethodFilterDropDown_littlespidy endpointMethodFilter;
    private AuthFilterDropDown_littlespidy endpointAuthFilter;
    private JLabel endpointMethodSummaryLabel;
    private JLabel endpointAuthSummaryLabel;
    private JTextField baseUrlField;

    private final List<Runnable> stateChangedListeners = new ArrayList<>();

    public interface SendToVersionFinderCallback {
        void onSendToVersionFinder(ImportedCollection_littlespidy collection, DiscoveredEndpoint_littlespidy endpoint);
    }
    private SendToVersionFinderCallback onSendToVersionFinderListener;

    public void setOnSendToVersionFinderListener(SendToVersionFinderCallback listener) {
        this.onSendToVersionFinderListener = listener;
    }

    public APIImportTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(8, 8));
        this.api = api;

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    public void addStateChangedListener(Runnable listener) {
        if (listener != null) {
            this.stateChangedListeners.add(listener);
        }
    }

    public void setOnStateChangedCallback(Runnable callback) {
        if (callback != null) {
            this.stateChangedListeners.add(callback);
        }
    }

    private void notifyStateChanged() {
        for (Runnable r : new ArrayList<>(stateChangedListeners)) {
            try {
                r.run();
            } catch (Exception ignored) {
            }
        }
    }

    private void initComponents() {
        // --- 1. Top Action Toolbar ---
        JPanel topBar = new JPanel(new BorderLayout(8, 4));
        topBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(4, 4, 8, 4)
        ));

        JPanel leftActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        JButton importFilesBtn = new JButton("Import File(s)...");
        importFilesBtn.setFont(importFilesBtn.getFont().deriveFont(Font.BOLD));
        importFilesBtn.setToolTipText("Import one or multiple OpenAPI, Swagger, or Postman files");
        importFilesBtn.addActionListener(e -> onImportFiles());
        leftActions.add(importFilesBtn);

        JButton importUrlBtn = new JButton("Import URL(s)...");
        importUrlBtn.setFont(importUrlBtn.getFont().deriveFont(Font.BOLD));
        importUrlBtn.setToolTipText("Fetch and parse OpenAPI, Swagger, or Postman specifications from URLs");
        importUrlBtn.addActionListener(e -> onImportUrls());
        leftActions.add(importUrlBtn);

        JButton refreshBtn = new JButton("Refresh / Reimport");
        refreshBtn.setToolTipText("Re-fetch URL or re-read file for selected collection");
        refreshBtn.addActionListener(e -> onRefreshCollection());
        leftActions.add(refreshBtn);

        JButton removeBtn = new JButton("Remove Collection");
        removeBtn.setToolTipText("Remove selected collection after confirmation");
        removeBtn.addActionListener(e -> onRemoveCollection());
        leftActions.add(removeBtn);

        topBar.add(leftActions, BorderLayout.WEST);

        JPanel rightStats = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        collectionCountLabel = new JLabel("Collections: 0");
        collectionCountLabel.setFont(collectionCountLabel.getFont().deriveFont(Font.PLAIN, 12f));
        rightStats.add(collectionCountLabel);

        topBar.add(rightStats, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // --- 2. Center: Split Pane (Collections Master Table on Top, Endpoints Details on Bottom) ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.42);
        splitPane.setContinuousLayout(true);

        // Top Pane: Collections Master View
        JPanel collectionsPanel = new JPanel(new BorderLayout(6, 6));
        collectionsPanel.setBorder(new TitledBorder("Imported API Definitions & Collections"));

        collectionTableModel = new CollectionTableModel();
        collectionTable = new JTable(collectionTableModel);
        collectionSorter = new TableRowSorter<>(collectionTableModel);
        collectionTable.setRowSorter(collectionSorter);
        collectionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        collectionTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onCollectionSelected();
            }
        });

        JScrollPane colScroll = new JScrollPane(collectionTable);
        collectionsPanel.add(colScroll, BorderLayout.CENTER);

        // Target Base URL Bar under collections table
        JPanel colConfigBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        colConfigBar.add(new JLabel("Target Base URL:"));
        baseUrlField = new JTextField(30);
        baseUrlField.setToolTipText("Target host override for constructing requests during testing");
        baseUrlField.addActionListener(e -> onBaseUrlChanged());
        colConfigBar.add(baseUrlField);

        JButton saveUrlBtn = new JButton("Update Base URL");
        saveUrlBtn.addActionListener(e -> onBaseUrlChanged());
        colConfigBar.add(saveUrlBtn);

        collectionsPanel.add(colConfigBar, BorderLayout.SOUTH);
        splitPane.setTopComponent(collectionsPanel);

        // Bottom Pane: Discovered Endpoints View
        JPanel endpointsPanel = new JPanel(new BorderLayout(6, 6));
        endpointsPanel.setBorder(new TitledBorder("Discovered Endpoints for Selected Collection"));

        JPanel endpointHeader = new JPanel();
        endpointHeader.setLayout(new BoxLayout(endpointHeader, BoxLayout.Y_AXIS));

        // Filters row: Search + Method Filter + Auth Filter + Clear
        JPanel filterRow = new JPanel(new BorderLayout(8, 2));
        JPanel searchBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        searchBox.add(new JLabel("Filter Endpoints:"));
        endpointSearchField = new JTextField(18);
        endpointSearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { filterEndpoints(); }
            @Override public void removeUpdate(DocumentEvent e) { filterEndpoints(); }
            @Override public void changedUpdate(DocumentEvent e) { filterEndpoints(); }
        });
        searchBox.add(endpointSearchField);

        endpointMethodFilter = new MethodFilterDropDown_littlespidy();
        endpointMethodFilter.addFilterChangeListener(this::filterEndpoints);
        searchBox.add(endpointMethodFilter);

        endpointAuthFilter = new AuthFilterDropDown_littlespidy();
        endpointAuthFilter.addFilterChangeListener(this::filterEndpoints);
        searchBox.add(endpointAuthFilter);

        JButton clearFilterBtn = new JButton("Clear Filters");
        clearFilterBtn.addActionListener(e -> {
            endpointSearchField.setText("");
            endpointMethodFilter.selectAll(true);
            endpointAuthFilter.selectAll(true);
            filterEndpoints();
        });
        searchBox.add(clearFilterBtn);
        filterRow.add(searchBox, BorderLayout.WEST);

        endpointCountLabel = new JLabel("Endpoints: 0");
        filterRow.add(endpointCountLabel, BorderLayout.EAST);
        endpointHeader.add(filterRow);

        // Summary row: Method breakdown & Auth breakdown
        JPanel summaryRow = new JPanel(new BorderLayout(6, 2));
        summaryRow.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        endpointMethodSummaryLabel = new JLabel("Methods: None");
        endpointMethodSummaryLabel.setFont(endpointMethodSummaryLabel.getFont().deriveFont(Font.PLAIN, 11f));
        summaryRow.add(endpointMethodSummaryLabel, BorderLayout.WEST);

        endpointAuthSummaryLabel = new JLabel("Auth Status: None");
        endpointAuthSummaryLabel.setFont(endpointAuthSummaryLabel.getFont().deriveFont(Font.PLAIN, 11f));
        summaryRow.add(endpointAuthSummaryLabel, BorderLayout.EAST);

        endpointHeader.add(summaryRow);
        endpointsPanel.add(endpointHeader, BorderLayout.NORTH);

        endpointTableModel = new EndpointTableModel();
        endpointTable = new JTable(endpointTableModel);
        endpointSorter = new TableRowSorter<>(endpointTableModel);
        endpointTable.setRowSorter(endpointSorter);
        endpointTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Double click opens endpoint details dialog, right click opens context menu
        endpointTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = endpointTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        int modelRow = endpointTable.convertRowIndexToModel(row);
                        DiscoveredEndpoint_littlespidy ep = endpointTableModel.getEndpointAt(modelRow);
                        if (ep != null) {
                            showEndpointDetailsDialog(ep);
                        }
                    }
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }

            private void showContextMenu(MouseEvent e) {
                int row = endpointTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    if (!endpointTable.isRowSelected(row)) {
                        endpointTable.setRowSelectionInterval(row, row);
                    }
                    int modelRow = endpointTable.convertRowIndexToModel(row);
                    DiscoveredEndpoint_littlespidy ep = endpointTableModel.getEndpointAt(modelRow);
                    if (ep != null) {
                        JPopupMenu menu = new JPopupMenu();

                        JMenuItem viewDetails = new JMenuItem("View Endpoint Details");
                        viewDetails.addActionListener(ev -> showEndpointDetailsDialog(ep));
                        menu.add(viewDetails);

                        menu.addSeparator();

                        JMenuItem sendToVF = new JMenuItem("Send to ResAPI Version Finder");
                        sendToVF.addActionListener(ev -> {
                            ImportedCollection_littlespidy col = getSelectedCollection();
                            if (col != null && onSendToVersionFinderListener != null) {
                                onSendToVersionFinderListener.onSendToVersionFinder(col, ep);
                            }
                        });
                        menu.add(sendToVF);

                        menu.show(endpointTable, e.getX(), e.getY());
                    }
                }
            }
        });

        JScrollPane epScroll = new JScrollPane(endpointTable);
        endpointsPanel.add(epScroll, BorderLayout.CENTER);

        splitPane.setBottomComponent(endpointsPanel);
        add(splitPane, BorderLayout.CENTER);
    }

    public void showEndpointDetailsDialog(DiscoveredEndpoint_littlespidy ep) {
        if (ep == null) return;
        Window parent = SwingUtilities.getWindowAncestor(this);
        Runnable sendToVFAction = () -> {
            ImportedCollection_littlespidy col = getSelectedCollection();
            if (col != null && onSendToVersionFinderListener != null) {
                onSendToVersionFinderListener.onSendToVersionFinder(col, ep);
            }
        };
        EndpointDetailsDialog_littlespidy dialog = new EndpointDetailsDialog_littlespidy(parent, ep, sendToVFAction);
        dialog.setVisible(true);
    }

    private void onImportFiles() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select API Specification Files");
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("API Definitions (*.json, *.yaml, *.yml)", "json", "yaml", "yml"));

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File[] files = chooser.getSelectedFiles();
            if (files != null && files.length > 0) {
                int successCount = 0;
                List<String> importErrors = new ArrayList<>();

                for (File f : files) {
                    try {
                        String content = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                        ParseResult_littlespidy parseRes = APIParserFactory_littlespidy.parse(content, f.getAbsolutePath(), "FILE");
                        if (parseRes.isSuccess() && parseRes.getCollection() != null) {
                            ImportedCollection_littlespidy col = parseRes.getCollection();
                            col.setSourceLocation(f.getAbsolutePath());
                            collections.add(col);
                            successCount++;
                        } else {
                            importErrors.add(f.getName() + ": " + parseRes.getErrorMessage());
                        }
                    } catch (Exception ex) {
                        importErrors.add(f.getName() + ": " + ex.getMessage());
                    }
                }

                collectionTableModel.fireTableDataChanged();
                updateStats();
                notifyStateChanged();

                if (!importErrors.isEmpty()) {
                    JOptionPane.showMessageDialog(this,
                            "Import completed: " + successCount + " imported, " + importErrors.size() + " failed.\n\n" +
                            String.join("\n", importErrors),
                            "Import Summary",
                            successCount == 0 ? JOptionPane.ERROR_MESSAGE : JOptionPane.WARNING_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this,
                            "Successfully imported " + successCount + " API definition(s).",
                            "Import Successful",
                            JOptionPane.INFORMATION_MESSAGE);
                }
            }
        }
    }

    private void onImportUrls() {
        Window parentWin = SwingUtilities.getWindowAncestor(this);
        URLImportDialog_littlespidy dialog = new URLImportDialog_littlespidy(parentWin, api);
        dialog.setVisible(true);

        if (dialog.isCompleted()) {
            List<ImportedCollection_littlespidy> imported = dialog.getImportedCollections();
            if (imported != null && !imported.isEmpty()) {
                collections.addAll(imported);
                collectionTableModel.fireTableDataChanged();
                updateStats();
                notifyStateChanged();
            }
        }
    }

    private void onRefreshCollection() {
        int row = collectionTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a collection to refresh.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = collectionTable.convertRowIndexToModel(row);
        ImportedCollection_littlespidy col = collections.get(modelRow);

        if ("FILE".equalsIgnoreCase(col.getSourceType())) {
            File f = new File(col.getSourceLocation());
            if (!f.exists()) {
                JOptionPane.showMessageDialog(this, "Source file no longer exists at: " + col.getSourceLocation(), "Refresh Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                String content = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                ParseResult_littlespidy parseRes = APIParserFactory_littlespidy.parse(content, f.getAbsolutePath(), "FILE");
                if (parseRes.isSuccess() && parseRes.getCollection() != null) {
                    ImportedCollection_littlespidy updated = parseRes.getCollection();
                    col.setEndpoints(updated.getEndpoints());
                    col.setFormatType(updated.getFormatType());
                    col.setImportStatus("Refreshed (" + updated.getEndpoints().size() + " endpoints)");
                    col.setImportedAt(System.currentTimeMillis());
                    collectionTableModel.fireTableRowsUpdated(modelRow, modelRow);
                    onCollectionSelected();
                    notifyStateChanged();
                    JOptionPane.showMessageDialog(this, "Collection refreshed successfully.", "Refresh", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this, "Failed to parse file: " + parseRes.getErrorMessage(), "Refresh Error", JOptionPane.ERROR_MESSAGE);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error re-reading file: " + ex.getMessage(), "Refresh Error", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            // URL Refresh
            Thread t = new Thread(() -> {
                try {
                    String urlStr = col.getSourceLocation();
                    String content = "";
                    if (api != null && api.http() != null) {
                        var req = burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(urlStr);
                        var reqResp = api.http().sendRequest(req);
                        if (reqResp != null && reqResp.hasResponse()) {
                            content = reqResp.response().bodyToString();
                        }
                    }
                    if (content.isBlank()) {
                        throw new RuntimeException("Empty response received from URL.");
                    }
                    ParseResult_littlespidy parseRes = APIParserFactory_littlespidy.parse(content, urlStr, "URL");
                    if (parseRes.isSuccess() && parseRes.getCollection() != null) {
                        ImportedCollection_littlespidy updated = parseRes.getCollection();
                        SwingUtilities.invokeLater(() -> {
                            col.setEndpoints(updated.getEndpoints());
                            col.setImportStatus("Refreshed (" + updated.getEndpoints().size() + " endpoints)");
                            col.setImportedAt(System.currentTimeMillis());
                            collectionTableModel.fireTableRowsUpdated(modelRow, modelRow);
                            onCollectionSelected();
                            notifyStateChanged();
                            JOptionPane.showMessageDialog(this, "Collection refreshed from URL successfully.", "Refresh", JOptionPane.INFORMATION_MESSAGE);
                        });
                    }
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(this, "Error refreshing URL: " + ex.getMessage(), "Refresh Error", JOptionPane.ERROR_MESSAGE);
                    });
                }
            });
            t.setDaemon(true);
            t.start();
        }
    }

    private void onRemoveCollection() {
        int row = collectionTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a collection to remove.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = collectionTable.convertRowIndexToModel(row);
        ImportedCollection_littlespidy col = collections.get(modelRow);

        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to remove the collection:\n\"" + col.getName() + "\" (" + col.getEndpointCount() + " endpoints)?",
                "Confirm Removal",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            collections.remove(modelRow);
            collectionTableModel.fireTableDataChanged();
            endpointTableModel.setEndpoints(null);
            baseUrlField.setText("");
            updateStats();
            updateEndpointSummary(Collections.emptyList());
            notifyStateChanged();
        }
    }

    private void onCollectionSelected() {
        int row = collectionTable.getSelectedRow();
        if (row < 0 || row >= collections.size()) {
            endpointTableModel.setEndpoints(null);
            endpointCountLabel.setText("Endpoints: 0");
            baseUrlField.setText("");
            updateEndpointSummary(Collections.emptyList());
            return;
        }
        int modelRow = collectionTable.convertRowIndexToModel(row);
        ImportedCollection_littlespidy col = collections.get(modelRow);

        endpointTableModel.setEndpoints(col.getEndpoints());
        baseUrlField.setText(col.getTargetBaseUrl() != null ? col.getTargetBaseUrl() : "");

        // Register any methods discovered in this collection
        for (DiscoveredEndpoint_littlespidy ep : col.getEndpoints()) {
            endpointMethodFilter.registerMethod(ep.getMethod());
        }

        updateEndpointSummary(col.getEndpoints());
        filterEndpoints();
    }

    private void updateEndpointSummary(List<DiscoveredEndpoint_littlespidy> endpoints) {
        if (endpoints == null || endpoints.isEmpty()) {
            endpointMethodSummaryLabel.setText("Methods: None");
            endpointAuthSummaryLabel.setText("Authentication: None");
            endpointCountLabel.setText("Endpoints: 0");
            return;
        }

        Map<String, Integer> methodCounts = new LinkedHashMap<>();
        int authRequiredCount = 0;
        int noAuthCount = 0;

        for (DiscoveredEndpoint_littlespidy ep : endpoints) {
            String m = ep.getMethod() != null ? ep.getMethod().toUpperCase(Locale.ROOT) : "GET";
            methodCounts.put(m, methodCounts.getOrDefault(m, 0) + 1);

            if (ep.isRequiresAuth()) {
                authRequiredCount++;
            } else {
                noAuthCount++;
            }
        }

        StringBuilder methodSb = new StringBuilder("Methods: ");
        List<String> methodParts = new ArrayList<>();
        for (Map.Entry<String, Integer> e : methodCounts.entrySet()) {
            methodParts.add(e.getKey() + ": " + e.getValue());
        }
        methodSb.append(String.join(" | ", methodParts));
        endpointMethodSummaryLabel.setText(methodSb.toString());

        endpointAuthSummaryLabel.setText(String.format("Auth: Required (%d) | No Auth (%d) | Total: %d",
                authRequiredCount, noAuthCount, endpoints.size()));
    }

    private void onBaseUrlChanged() {
        int row = collectionTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = collectionTable.convertRowIndexToModel(row);
        ImportedCollection_littlespidy col = collections.get(modelRow);
        col.setTargetBaseUrl(baseUrlField.getText().trim());
        collectionTableModel.fireTableCellUpdated(modelRow, 3);
        notifyStateChanged();
    }

    private void filterEndpoints() {
        if (endpointSorter == null) return;

        endpointSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends EndpointTableModel, ? extends Integer> entry) {
                int modelRow = entry.getIdentifier();
                DiscoveredEndpoint_littlespidy ep = endpointTableModel.getEndpointAt(modelRow);
                if (ep == null) return false;

                // 1. HTTP Method multi-select filter
                if (endpointMethodFilter != null && !endpointMethodFilter.isMethodSelected(ep.getMethod())) {
                    return false;
                }

                // 2. Authentication requirement multi-select filter
                if (endpointAuthFilter != null && !endpointAuthFilter.isAuthOptionSelected(ep.isRequiresAuth())) {
                    return false;
                }

                // 3. Search text query
                String query = endpointSearchField.getText().trim();
                if (!query.isEmpty()) {
                    String q = query.toLowerCase(Locale.ROOT);
                    boolean matches = ep.getPath().toLowerCase(Locale.ROOT).contains(q)
                            || ep.getMethod().toLowerCase(Locale.ROOT).contains(q)
                            || ep.getSummary().toLowerCase(Locale.ROOT).contains(q)
                            || ep.getParametersSummary().toLowerCase(Locale.ROOT).contains(q);
                    if (!matches) {
                        return false;
                    }
                }

                return true;
            }
        });

        int displayed = endpointTable.getRowCount();
        int total = endpointTableModel.getRowCount();
        endpointCountLabel.setText("Showing " + displayed + " of " + total + " Endpoints");
    }

    public void updateAvailableProfiles(List<AuthProfile_littlespidy> profiles) {
        this.availableProfiles.clear();
        if (profiles != null) {
            this.availableProfiles.addAll(profiles);
        }
        collectionTableModel.fireTableDataChanged();
    }

    public void updateStats() {
        collectionCountLabel.setText("Collections: " + collections.size());
    }

    public List<ImportedCollection_littlespidy> getAllCollections() {
        return collections;
    }

    public void setCollections(List<ImportedCollection_littlespidy> list) {
        collections.clear();
        if (list != null) {
            collections.addAll(list);
        }
        collectionTableModel.fireTableDataChanged();
        endpointTableModel.setEndpoints(null);
        baseUrlField.setText("");
        updateStats();
        updateEndpointSummary(Collections.emptyList());
        notifyStateChanged();
    }

    public ImportedCollection_littlespidy getSelectedCollection() {
        int row = collectionTable.getSelectedRow();
        if (row < 0 || row >= collections.size()) return null;
        int modelRow = collectionTable.convertRowIndexToModel(row);
        return collections.get(modelRow);
    }

    // --- Table Models ---

    private class CollectionTableModel extends AbstractTableModel {
        private final String[] columns = {"Name", "Format", "Source", "Target Base URL", "Endpoints", "Status"};

        @Override public int getRowCount() { return collections.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            ImportedCollection_littlespidy c = collections.get(row);
            switch (col) {
                case 0: return c.getName();
                case 1: return c.getFormatType();
                case 2: return c.getSourceType() + ": " + abbreviate(c.getSourceLocation(), 35);
                case 3: return c.getTargetBaseUrl();
                case 4: return c.getEndpointCount();
                case 5: return c.getImportStatus();
                default: return "";
            }
        }

        private String abbreviate(String s, int max) {
            if (s == null) return "";
            if (s.length() <= max) return s;
            return "..." + s.substring(s.length() - max);
        }
    }

    private static class EndpointTableModel extends AbstractTableModel {
        private final String[] columns = {"Method", "Path", "Summary", "Parameters", "Requires Auth"};
        private List<DiscoveredEndpoint_littlespidy> endpoints = new ArrayList<>();

        public void setEndpoints(List<DiscoveredEndpoint_littlespidy> list) {
            this.endpoints = (list != null) ? list : new ArrayList<>();
            fireTableDataChanged();
        }

        public DiscoveredEndpoint_littlespidy getEndpointAt(int row) {
            if (row >= 0 && row < endpoints.size()) return endpoints.get(row);
            return null;
        }

        @Override public int getRowCount() { return endpoints.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            DiscoveredEndpoint_littlespidy ep = endpoints.get(row);
            switch (col) {
                case 0: return ep.getMethod();
                case 1: return ep.getPath();
                case 2: return ep.getSummary();
                case 3: return ep.getParametersSummary();
                case 4: return ep.isRequiresAuth() ? "Yes" : "No";
                default: return "";
            }
        }
    }
}
