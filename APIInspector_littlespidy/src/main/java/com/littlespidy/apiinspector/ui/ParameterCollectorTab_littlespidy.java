// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tab dedicated to parameter collection and extraction across API endpoints.
 * Displays all query, path, and body parameters in structured tables with parameter data types
 * and one-click copy icons for copying parameter values.
 */
public class ParameterCollectorTab_littlespidy extends JPanel {

    private final List<ImportedCollection_littlespidy> collections = new ArrayList<>();
    private final List<ParameterEntry> queryParamsList = new ArrayList<>();
    private final List<ParameterEntry> pathParamsList = new ArrayList<>();
    private final List<ParameterEntry> bodyParamsList = new ArrayList<>();

    private JComboBox<CollectionComboItem> collectionSelector;
    private JLabel summaryLabel;
    private JLabel copyFeedbackLabel;

    private ParameterTableModel queryTableModel;
    private JTable queryTable;
    private TableRowSorter<ParameterTableModel> querySorter;
    private JTextField querySearchField;

    private ParameterTableModel pathTableModel;
    private JTable pathTable;
    private TableRowSorter<ParameterTableModel> pathSorter;
    private JTextField pathSearchField;

    private ParameterTableModel bodyTableModel;
    private JTable bodyTable;
    private TableRowSorter<ParameterTableModel> bodySorter;
    private JTextField bodySearchField;

    public interface ParameterDoubleClickListener {
        void onParameterDoubleClicked(DiscoveredEndpoint_littlespidy endpoint, ParameterEntry parameter);
    }

    public interface SendToVersionFinderListener {
        void onSendToVersionFinder(DiscoveredEndpoint_littlespidy endpoint);
    }

    private ParameterDoubleClickListener onParameterDoubleClickListener;
    private SendToVersionFinderListener onSendToVersionFinderListener;

    public void setOnParameterDoubleClickListener(ParameterDoubleClickListener listener) {
        this.onParameterDoubleClickListener = listener;
    }

    public void setOnSendToVersionFinderListener(SendToVersionFinderListener listener) {
        this.onSendToVersionFinderListener = listener;
    }

    private static final Pattern PATH_VARIABLE_PATTERN = Pattern.compile("\\{([a-zA-Z0-9_\\-]+)\\}|:([a-zA-Z0-9_\\-]+)");

    public ParameterCollectorTab_littlespidy() {
        super(new BorderLayout(6, 6));
        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    private void initComponents() {
        // --- Top Bar: Collection Selector, Global Copy All Combined, Summary ---
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        JPanel topBar = new JPanel(new BorderLayout(8, 4));
        JPanel leftActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        leftActions.add(new JLabel("Collection:"));
        collectionSelector = new JComboBox<>();
        collectionSelector.setPreferredSize(new Dimension(240, 26));
        collectionSelector.addActionListener(e -> rebuildParameterLists());
        leftActions.add(collectionSelector);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> rebuildParameterLists());
        leftActions.add(refreshBtn);

        JButton copyAllCombinedBtn = new JButton("Copy All (Query + Path + Body)");
        copyAllCombinedBtn.setFont(copyAllCombinedBtn.getFont().deriveFont(Font.BOLD));
        copyAllCombinedBtn.setToolTipText("Copy combined unique list of all parameters (Query, Path, Body) (one per line) to clipboard");
        copyAllCombinedBtn.addActionListener(e -> copyCombinedList());
        leftActions.add(copyAllCombinedBtn);

        topBar.add(leftActions, BorderLayout.WEST);

        JPanel rightStats = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 2));
        summaryLabel = new JLabel("Query Params: 0 | Path Params: 0 | Body Params: 0");
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.PLAIN, 12f));
        rightStats.add(summaryLabel);
        topBar.add(rightStats, BorderLayout.EAST);

        topContainer.add(topBar);

        // Feedback notification banner
        JPanel feedbackBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        copyFeedbackLabel = new JLabel(" ");
        copyFeedbackLabel.setFont(copyFeedbackLabel.getFont().deriveFont(Font.ITALIC, 11f));
        copyFeedbackLabel.setForeground(new Color(0, 120, 40));
        feedbackBar.add(copyFeedbackLabel);
        topContainer.add(feedbackBar);

        add(topContainer, BorderLayout.NORTH);

        // --- Center: 3-way Split Pane for Query, Path, and Body Parameters ---
        JPanel querySection = createQuerySection();
        JPanel pathSection = createPathSection();
        JPanel bodySection = createBodySection();

        JSplitPane innerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, pathSection, bodySection);
        innerSplit.setResizeWeight(0.5);
        innerSplit.setContinuousLayout(true);

        JSplitPane outerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, querySection, innerSplit);
        outerSplit.setResizeWeight(0.33);
        outerSplit.setContinuousLayout(true);

        add(outerSplit, BorderLayout.CENTER);
    }

    private JPanel createQuerySection() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new TitledBorder("Query Parameters"));

        JPanel headerBar = new JPanel(new BorderLayout(6, 2));
        JPanel searchBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        searchBox.add(new JLabel("Filter:"));
        querySearchField = new JTextField(14);
        querySearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { filterQueryTable(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { filterQueryTable(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { filterQueryTable(); }
        });
        searchBox.add(querySearchField);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> querySearchField.setText(""));
        searchBox.add(clearBtn);
        headerBar.add(searchBox, BorderLayout.WEST);
        panel.add(headerBar, BorderLayout.NORTH);

        // Query Parameters Table
        queryTableModel = new ParameterTableModel(queryParamsList);
        queryTable = new JTable(queryTableModel);
        querySorter = new TableRowSorter<>(queryTableModel);
        queryTable.setRowSorter(querySorter);
        queryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupTableRenderersAndListeners(queryTable, queryTableModel);

        panel.add(new JScrollPane(queryTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createPathSection() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new TitledBorder("Path Parameters"));

        JPanel headerBar = new JPanel(new BorderLayout(6, 2));
        JPanel searchBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        searchBox.add(new JLabel("Filter:"));
        pathSearchField = new JTextField(14);
        pathSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { filterPathTable(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { filterPathTable(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { filterPathTable(); }
        });
        searchBox.add(pathSearchField);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> pathSearchField.setText(""));
        searchBox.add(clearBtn);
        headerBar.add(searchBox, BorderLayout.WEST);
        panel.add(headerBar, BorderLayout.NORTH);

        // Path Parameters Table
        pathTableModel = new ParameterTableModel(pathParamsList);
        pathTable = new JTable(pathTableModel);
        pathSorter = new TableRowSorter<>(pathTableModel);
        pathTable.setRowSorter(pathSorter);
        pathTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupTableRenderersAndListeners(pathTable, pathTableModel);

        panel.add(new JScrollPane(pathTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createBodySection() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new TitledBorder("Body Parameters"));

        JPanel headerBar = new JPanel(new BorderLayout(6, 2));
        JPanel searchBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        searchBox.add(new JLabel("Filter:"));
        bodySearchField = new JTextField(14);
        bodySearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { filterBodyTable(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { filterBodyTable(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { filterBodyTable(); }
        });
        searchBox.add(bodySearchField);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> bodySearchField.setText(""));
        searchBox.add(clearBtn);
        headerBar.add(searchBox, BorderLayout.WEST);
        panel.add(headerBar, BorderLayout.NORTH);

        // Body Parameters Table
        bodyTableModel = new ParameterTableModel(bodyParamsList);
        bodyTable = new JTable(bodyTableModel);
        bodySorter = new TableRowSorter<>(bodyTableModel);
        bodyTable.setRowSorter(bodySorter);
        bodyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupTableRenderersAndListeners(bodyTable, bodyTableModel);

        panel.add(new JScrollPane(bodyTable), BorderLayout.CENTER);
        return panel;
    }

    private void setupTableRenderersAndListeners(JTable table, ParameterTableModel model) {
        // Plain text renderer for Column 0 (Parameter Name) - per-parameter copy button removed
        table.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer());

        // Install Column 0 Header Renderer with a dedicated "Copy" button on the column name "Parameter"
        table.getColumnModel().getColumn(0).setHeaderRenderer(new ParameterHeaderRenderer());

        // Header click listener: Clicking on the Copy button on the "Parameter" column header copies all parameters from the table
        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int col = table.getTableHeader().columnAtPoint(e.getPoint());
                if (col == 0) {
                    Rectangle rect = table.getTableHeader().getHeaderRect(col);
                    int xInCol = e.getX() - rect.x;
                    // If clicked in the right 55 pixels of the header cell (the Copy button area)
                    if (xInCol >= rect.width - 55) {
                        copyAllParametersFromTable(table, model);
                        e.consume();
                    }
                }
            }
        });

        // Table mouse listener: Double-click navigates to exact request in Request & Response Viewer tab
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        int modelRow = table.convertRowIndexToModel(row);
                        ParameterEntry entry = model.getEntry(modelRow);
                        if (entry != null && onParameterDoubleClickListener != null) {
                            DiscoveredEndpoint_littlespidy ep = entry.getFirstEndpoint();
                            onParameterDoubleClickListener.onParameterDoubleClicked(ep, entry);
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
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    if (!table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    int modelRow = table.convertRowIndexToModel(row);
                    ParameterEntry entry = model.getEntry(modelRow);
                    if (entry != null) {
                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem copyParamItem = new JMenuItem("Copy Parameter Name");
                        copyParamItem.addActionListener(ev -> {
                            copyToClipboard(entry.name);
                            showFeedback("Copied parameter '" + entry.name + "' to clipboard.");
                        });
                        menu.add(copyParamItem);

                        JMenuItem copyValItem = new JMenuItem("Copy Sample Value");
                        copyValItem.addActionListener(ev -> copyParameterValue(entry));
                        menu.add(copyValItem);

                        menu.addSeparator();

                        JMenuItem sendToVF = new JMenuItem("Send to ResAPI Version Finder");
                        sendToVF.setEnabled(entry.getFirstEndpoint() != null);
                        sendToVF.addActionListener(ev -> {
                            if (entry.getFirstEndpoint() != null && onSendToVersionFinderListener != null) {
                                onSendToVersionFinderListener.onSendToVersionFinder(entry.getFirstEndpoint());
                            }
                        });
                        menu.add(sendToVF);

                        menu.show(table, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void copyAllParametersFromTable(JTable table, ParameterTableModel model) {
        int rowCount = table.getRowCount();
        if (rowCount == 0) {
            showFeedback("No parameters available to copy in this table.");
            return;
        }

        Set<String> names = new LinkedHashSet<>();
        for (int i = 0; i < rowCount; i++) {
            int modelRow = table.convertRowIndexToModel(i);
            ParameterEntry entry = model.getEntry(modelRow);
            if (entry != null && entry.name != null && !entry.name.isBlank()) {
                names.add(entry.name);
            }
        }

        if (names.isEmpty()) {
            showFeedback("No parameters found.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            sb.append(n).append("\n");
        }
        copyToClipboard(sb.toString().trim());
        showFeedback("Copied " + names.size() + " parameter(s) from " + table.getColumnName(0) + " column to clipboard.");
    }

    public static class ParameterHeaderRenderer extends JPanel implements TableCellRenderer {
        private final JLabel label;
        private final JButton copyButton;

        public ParameterHeaderRenderer() {
            super(new BorderLayout(4, 0));
            setOpaque(true);

            label = new JLabel("Parameter");
            label.setFont(label.getFont().deriveFont(Font.BOLD));

            copyButton = new JButton("Copy");
            copyButton.setFocusable(false);
            copyButton.setFont(copyButton.getFont().deriveFont(Font.PLAIN, 10f));
            copyButton.setMargin(new Insets(1, 4, 1, 4));
            copyButton.setToolTipText("Copy all parameters in this column to clipboard");

            setBorder(BorderFactory.createCompoundBorder(
                    UIManager.getBorder("TableHeader.cellBorder"),
                    BorderFactory.createEmptyBorder(0, 4, 0, 4)
            ));

            add(label, BorderLayout.CENTER);
            add(copyButton, BorderLayout.EAST);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            if (value != null) {
                label.setText(value.toString());
            }
            if (table != null && table.getTableHeader() != null) {
                setBackground(table.getTableHeader().getBackground());
                setForeground(table.getTableHeader().getForeground());
            }
            return this;
        }
    }

    public synchronized void updateCollections(List<ImportedCollection_littlespidy> cols) {
        collections.clear();
        if (cols != null) {
            collections.addAll(cols);
        }

        // Temporarily detach action listeners during combo rebuild
        java.awt.event.ActionListener[] listeners = collectionSelector.getActionListeners();
        for (java.awt.event.ActionListener al : listeners) {
            collectionSelector.removeActionListener(al);
        }

        collectionSelector.removeAllItems();
        collectionSelector.addItem(new CollectionComboItem(null, "[All Imported Collections]"));
        for (ImportedCollection_littlespidy c : collections) {
            collectionSelector.addItem(new CollectionComboItem(c, c.getName() + " (" + c.getEndpointCount() + ")"));
        }
        collectionSelector.setSelectedIndex(0);

        for (java.awt.event.ActionListener al : listeners) {
            collectionSelector.addActionListener(al);
        }

        rebuildParameterLists();
    }

    public static class DiscoveredParameters {
        public final Map<String, ParameterEntry> queryParams = new LinkedHashMap<>();
        public final Map<String, ParameterEntry> pathParams = new LinkedHashMap<>();
        public final Map<String, ParameterEntry> bodyParams = new LinkedHashMap<>();
    }

    public static DiscoveredParameters collectParameters(List<ImportedCollection_littlespidy> targetCols) {
        DiscoveredParameters result = new DiscoveredParameters();
        if (targetCols == null) return result;

        for (ImportedCollection_littlespidy col : targetCols) {
            if (col == null || col.getEndpoints() == null) continue;
            for (DiscoveredEndpoint_littlespidy ep : col.getEndpoints()) {
                if (ep == null) continue;
                ep.ensureParametersDiscovered();
                String epDesc = ep.getMethod() + " " + ep.getPath();

                // 1. Query parameters from endpoint queryParams map
                if (ep.getQueryParams() != null) {
                    for (Map.Entry<String, String> qEntry : ep.getQueryParams().entrySet()) {
                        String name = qEntry.getKey();
                        if (name == null || name.isBlank()) continue;
                        name = name.trim();
                        String val = qEntry.getValue() != null ? qEntry.getValue() : "";

                        ParameterEntry p = result.queryParams.computeIfAbsent(name, ParameterEntry::new);
                        p.addEndpoint(epDesc, ep);
                        if (p.sampleValue.isEmpty() && !val.isEmpty()) {
                            p.sampleValue = val;
                        }
                        String dt = ep.getQueryParamTypes().get(name);
                        if (dt != null && !dt.isBlank()) {
                            p.dataType = dt;
                        } else if (p.dataType == null || "string".equals(p.dataType)) {
                            p.dataType = inferDataType(val);
                        }
                    }
                }

                // 2. Query parameters embedded in URL path (e.g. /search?query=test&limit=10)
                if (ep.getPath() != null && ep.getPath().contains("?")) {
                    String qStr = ep.getPath().substring(ep.getPath().indexOf('?') + 1);
                    String[] pairs = qStr.split("&");
                    for (String pair : pairs) {
                        if (!pair.isBlank()) {
                            int eq = pair.indexOf('=');
                            String qName = eq > 0 ? pair.substring(0, eq).trim() : pair.trim();
                            String qVal = eq > 0 && eq < pair.length() - 1 ? pair.substring(eq + 1).trim() : "";
                            if (!qName.isBlank()) {
                                ParameterEntry p = result.queryParams.computeIfAbsent(qName, ParameterEntry::new);
                                p.addEndpoint(epDesc, ep);
                                if (p.sampleValue.isEmpty() && !qVal.isEmpty()) {
                                    p.sampleValue = qVal;
                                }
                                if (p.dataType == null || "string".equals(p.dataType)) {
                                    p.dataType = inferDataType(qVal);
                                }
                            }
                        }
                    }
                }

                // 3. Path parameters from explicit map
                if (ep.getPathParams() != null) {
                    for (Map.Entry<String, String> pEntry : ep.getPathParams().entrySet()) {
                        String name = pEntry.getKey();
                        if (name == null || name.isBlank()) continue;
                        name = name.trim();
                        String val = pEntry.getValue() != null ? pEntry.getValue() : "";

                        ParameterEntry p = result.pathParams.computeIfAbsent(name, ParameterEntry::new);
                        p.addEndpoint(epDesc, ep);
                        if (p.sampleValue.isEmpty() && !val.isEmpty()) {
                            p.sampleValue = val;
                        }
                        String dt = ep.getPathParamTypes().get(name);
                        if (dt != null && !dt.isBlank()) {
                            p.dataType = dt;
                        } else if (p.dataType == null || "string".equals(p.dataType)) {
                            p.dataType = inferDataType(val);
                        }
                    }
                }

                // 4. Extract path parameters from template variables in path (e.g. /users/{id} or /items/:code)
                if (ep.getPath() != null) {
                    String cleanPath = ep.getPath().contains("?") ? ep.getPath().substring(0, ep.getPath().indexOf('?')) : ep.getPath();
                    Matcher m = PATH_VARIABLE_PATTERN.matcher(cleanPath);
                    while (m.find()) {
                        String name = m.group(1) != null ? m.group(1) : m.group(2);
                        if (name != null && !name.isBlank()) {
                            name = name.trim();
                            ParameterEntry p = result.pathParams.computeIfAbsent(name, ParameterEntry::new);
                            p.addEndpoint(epDesc, ep);
                            if (p.dataType == null) {
                                p.dataType = "string";
                            }
                        }
                    }
                }

                // 5. Body parameters from explicit map
                if (ep.getBodyParams() != null) {
                    for (Map.Entry<String, String> bEntry : ep.getBodyParams().entrySet()) {
                        String name = bEntry.getKey();
                        if (name == null || name.isBlank()) continue;
                        name = name.trim();
                        String val = bEntry.getValue() != null ? bEntry.getValue() : "";

                        ParameterEntry p = result.bodyParams.computeIfAbsent(name, ParameterEntry::new);
                        p.addEndpoint(epDesc, ep);
                        if (p.sampleValue.isEmpty() && !val.isEmpty()) {
                            p.sampleValue = val;
                        }
                        String dt = ep.getBodyParamTypes().get(name);
                        if (dt != null && !dt.isBlank()) {
                            p.dataType = dt;
                        } else if (p.dataType == null || "string".equals(p.dataType)) {
                            p.dataType = inferDataType(val);
                        }
                    }
                }

                // 6. Body parameters from requestBodySample (JSON / form-encoded)
                if (ep.getRequestBodySample() != null && !ep.getRequestBodySample().isBlank()) {
                    String sample = ep.getRequestBodySample().trim();
                    if (sample.startsWith("{") || sample.startsWith("[")) {
                        try {
                            JsonElement el = JsonParser.parseString(sample);
                            extractJsonParamsRecursively(el, "", result.bodyParams, epDesc, ep);
                        } catch (Exception ignored) {}
                    }
                }
            }
        }
        return result;
    }

    private static void extractJsonParamsRecursively(
            JsonElement el,
            String prefix,
            Map<String, ParameterEntry> bodyMap,
            String epDesc,
            DiscoveredEndpoint_littlespidy ep) {
        if (el == null || el.isJsonNull()) return;
        if (el.isJsonObject()) {
            JsonObject obj = el.getAsJsonObject();
            for (Map.Entry<String, JsonElement> e : obj.entrySet()) {
                String key = e.getKey();
                String fullPath = prefix.isEmpty() ? key : prefix + "." + key;
                JsonElement v = e.getValue();
                if (v.isJsonPrimitive()) {
                    JsonPrimitive prim = v.getAsJsonPrimitive();
                    ParameterEntry p = bodyMap.computeIfAbsent(fullPath, ParameterEntry::new);
                    p.addEndpoint(epDesc, ep);
                    if (p.sampleValue.isEmpty()) {
                        p.sampleValue = prim.getAsString();
                    }
                    if (prim.isBoolean()) p.dataType = "boolean";
                    else if (prim.isNumber()) p.dataType = "number";
                    else p.dataType = "string";
                } else if (v.isJsonObject()) {
                    extractJsonParamsRecursively(v, fullPath, bodyMap, epDesc, ep);
                } else if (v.isJsonArray()) {
                    ParameterEntry p = bodyMap.computeIfAbsent(fullPath, ParameterEntry::new);
                    p.addEndpoint(epDesc, ep);
                    p.dataType = "array";
                }
            }
        }
    }

    public synchronized void rebuildParameterLists() {
        queryParamsList.clear();
        pathParamsList.clear();
        bodyParamsList.clear();

        CollectionComboItem sel = (CollectionComboItem) collectionSelector.getSelectedItem();
        List<ImportedCollection_littlespidy> targetCols = new ArrayList<>();
        if (sel == null || sel.collection == null) {
            targetCols.addAll(collections);
        } else {
            targetCols.add(sel.collection);
        }

        DiscoveredParameters discovered = collectParameters(targetCols);
        queryParamsList.addAll(discovered.queryParams.values());
        pathParamsList.addAll(discovered.pathParams.values());
        bodyParamsList.addAll(discovered.bodyParams.values());

        queryTableModel.fireTableDataChanged();
        pathTableModel.fireTableDataChanged();
        bodyTableModel.fireTableDataChanged();

        summaryLabel.setText("Query Params: " + queryParamsList.size() + " | Path Params: " + pathParamsList.size() + " | Body Params: " + bodyParamsList.size());
    }

    public static String inferDataType(String val) {
        if (val == null || val.isBlank()) {
            return "string";
        }
        String v = val.trim();
        if ("true".equalsIgnoreCase(v) || "false".equalsIgnoreCase(v)) {
            return "boolean";
        }
        if (v.matches("^-?\\d+$")) {
            return "integer";
        }
        if (v.matches("^-?\\d+\\.\\d+$")) {
            return "number";
        }
        if (v.startsWith("[") && v.endsWith("]")) {
            return "array";
        }
        if (v.startsWith("{") && v.endsWith("}")) {
            return "object";
        }
        return "string";
    }

    private void filterQueryTable() {
        String q = querySearchField.getText().trim();
        if (q.isEmpty()) {
            querySorter.setRowFilter(null);
        } else {
            querySorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
        }
    }

    private void filterPathTable() {
        String q = pathSearchField.getText().trim();
        if (q.isEmpty()) {
            pathSorter.setRowFilter(null);
        } else {
            pathSorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
        }
    }

    private void filterBodyTable() {
        String q = bodySearchField.getText().trim();
        if (q.isEmpty()) {
            bodySorter.setRowFilter(null);
        } else {
            bodySorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
        }
    }

    private void copyParameterValue(ParameterEntry entry) {
        if (entry == null) return;
        String val = (entry.sampleValue != null && !entry.sampleValue.isBlank()) ? entry.sampleValue : "";
        copyToClipboard(val);
        if (!val.isEmpty()) {
            showFeedback("Copied value '" + val + "' for parameter '" + entry.name + "' to clipboard.");
        } else {
            showFeedback("Copied empty value for parameter '" + entry.name + "' to clipboard.");
        }
    }

    private void copyCombinedList() {
        Set<String> unique = new LinkedHashSet<>();
        for (ParameterEntry p : queryParamsList) {
            unique.add(p.name);
        }
        for (ParameterEntry p : pathParamsList) {
            unique.add(p.name);
        }
        for (ParameterEntry p : bodyParamsList) {
            unique.add(p.name);
        }

        if (unique.isEmpty()) {
            showFeedback("No parameters found to copy.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (String s : unique) {
            sb.append(s).append("\n");
        }
        copyToClipboard(sb.toString().trim());
        showFeedback("Copied " + unique.size() + " combined parameters (one per line) to clipboard.");
    }

    private void copyToClipboard(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (Exception ex) {
            // Ignore clipboard errors
        }
    }

    private void showFeedback(String message) {
        copyFeedbackLabel.setText(message);
        javax.swing.Timer timer = new javax.swing.Timer(4000, e -> copyFeedbackLabel.setText(" "));
        timer.setRepeats(false);
        timer.start();
    }

    public List<ParameterEntry> getQueryParamsList() {
        return queryParamsList;
    }

    public List<ParameterEntry> getPathParamsList() {
        return pathParamsList;
    }

    public List<ParameterEntry> getBodyParamsList() {
        return bodyParamsList;
    }

    public JTable getQueryTable() {
        return queryTable;
    }

    public JTable getPathTable() {
        return pathTable;
    }

    public JTable getBodyTable() {
        return bodyTable;
    }

    // --- Vector Copy Icon (Strictly ASCII / Java2D Vector - Zero Emojis) ---
    public static class CopyIcon_littlespidy implements Icon {
        private final int width;
        private final int height;

        public CopyIcon_littlespidy() {
            this(14, 14);
        }

        public CopyIcon_littlespidy(int width, int height) {
            this.width = width;
            this.height = height;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            // Back document outline
            g2.setColor(Color.GRAY);
            g2.drawRect(x + 3, y, width - 5, height - 5);

            // Front document body & outline
            g2.setColor(c != null ? c.getBackground() : Color.WHITE);
            g2.fillRect(x, y + 3, width - 5, height - 5);
            g2.setColor(Color.DARK_GRAY);
            g2.drawRect(x, y + 3, width - 5, height - 5);

            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return width;
        }

        @Override
        public int getIconHeight() {
            return height;
        }
    }

    // --- Data structures & Table model ---

    public static class ParameterEntry {
        public final String name;
        public String sampleValue = "";
        public String dataType = "string";
        public final Set<String> endpoints = new LinkedHashSet<>();
        public final List<DiscoveredEndpoint_littlespidy> endpointObjects = new ArrayList<>();

        public ParameterEntry(String name) {
            this.name = name;
        }

        public void addEndpoint(String ep) {
            addEndpoint(ep, null);
        }

        public void addEndpoint(String ep, DiscoveredEndpoint_littlespidy endpointObj) {
            if (ep != null) endpoints.add(ep);
            if (endpointObj != null && !endpointObjects.contains(endpointObj)) {
                endpointObjects.add(endpointObj);
            }
        }

        public DiscoveredEndpoint_littlespidy getFirstEndpoint() {
            return endpointObjects.isEmpty() ? null : endpointObjects.get(0);
        }
    }

    public static class ParameterTableModel extends AbstractTableModel {
        private final String[] columns = {"Parameter", "Sample Value", "Endpoints Used", "Data Type"};
        private final List<ParameterEntry> entries;

        public ParameterTableModel(List<ParameterEntry> entries) {
            this.entries = entries;
        }

        public ParameterEntry getEntry(int row) {
            if (row >= 0 && row < entries.size()) {
                return entries.get(row);
            }
            return null;
        }

        @Override public int getRowCount() { return entries.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= entries.size()) return "";
            ParameterEntry p = entries.get(row);
            switch (col) {
                case 0: return p.name;
                case 1: return p.sampleValue.isEmpty() ? "-" : p.sampleValue;
                case 2: return p.endpoints.size() + " endpoint(s)";
                case 3: return (p.dataType != null && !p.dataType.isBlank()) ? p.dataType : "string";
                default: return "";
            }
        }
    }

    private static class CollectionComboItem {
        public final ImportedCollection_littlespidy collection;
        public final String label;

        public CollectionComboItem(ImportedCollection_littlespidy collection, String label) {
            this.collection = collection;
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }
}
