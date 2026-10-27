// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.littlespidy.apiinspector.model.SessionStore_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dedicated modeless dialog providing structured editing of Path, Query, and Body parameters.
 * Employs comprehensive collection-wide auto-population matching Parameter Collector discovery,
 * visual identification of empty vs pre-filled values, and non-destructive in-place request modification
 * to preserve custom headers, authentication tokens, and nested JSON structures.
 */
public class FillParametersDialog_littlespidy extends JDialog {

    private static final Pattern PATH_VARIABLE_PATTERN = Pattern.compile("\\{([a-zA-Z0-9_\\-]+)\\}|:([a-zA-Z0-9_\\-]+)");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final DiscoveredEndpoint_littlespidy endpoint;
    private final ImportedCollection_littlespidy initialCollection;
    private final List<ImportedCollection_littlespidy> allCollections = new ArrayList<>();
    private final String targetBaseUrl;
    private String currentRawRequest;
    private final SessionStore_littlespidy sessionStore;
    private final Consumer<HttpRequest> onApplyCallback;

    private JComboBox<CollectionComboItem> collectionSelector;
    private JTabbedPane tabbedPane;

    private DefaultTableModel pathTableModel;
    private DefaultTableModel queryTableModel;
    private DefaultTableModel bodyTableModel;

    private JTable pathTable;
    private JTable queryTable;
    private JTable bodyTable;

    private TableRowSorter<DefaultTableModel> pathSorter;
    private TableRowSorter<DefaultTableModel> querySorter;
    private TableRowSorter<DefaultTableModel> bodySorter;

    private JCheckBox pathEmptyOnlyCheck;
    private JCheckBox queryEmptyOnlyCheck;
    private JCheckBox bodyEmptyOnlyCheck;

    private final Set<String> originalActivePathKeys = new HashSet<>();
    private final Set<String> originalActiveQueryKeys = new HashSet<>();
    private final Set<String> originalActiveBodyKeys = new HashSet<>();

    public FillParametersDialog_littlespidy(
            Window owner,
            DiscoveredEndpoint_littlespidy endpoint,
            ImportedCollection_littlespidy initialCollection,
            List<ImportedCollection_littlespidy> allCollections,
            String targetBaseUrl,
            String currentRawRequest,
            SessionStore_littlespidy sessionStore,
            Consumer<HttpRequest> onApplyCallback) {
        super(owner, "Fill Parameters - " + (endpoint != null ? endpoint.getMethod() + " " + endpoint.getPath() : ""), ModalityType.MODELESS);
        this.endpoint = endpoint;
        this.initialCollection = initialCollection;
        if (allCollections != null) {
            this.allCollections.addAll(allCollections);
        } else if (initialCollection != null) {
            this.allCollections.add(initialCollection);
        }
        this.targetBaseUrl = targetBaseUrl != null && !targetBaseUrl.isBlank() ? targetBaseUrl : "https://localhost";
        this.currentRawRequest = (currentRawRequest != null && !currentRawRequest.isBlank())
                ? currentRawRequest
                : (endpoint != null && endpoint.hasCustomRequest() ? endpoint.getCustomRawRequest() : "");
        this.sessionStore = sessionStore;
        this.onApplyCallback = onApplyCallback;

        initComponents();
        setSize(800, 560);
        setLocationRelativeTo(owner);
    }

    public FillParametersDialog_littlespidy(
            Window owner,
            DiscoveredEndpoint_littlespidy endpoint,
            String targetBaseUrl,
            String currentRawRequest,
            SessionStore_littlespidy sessionStore,
            Consumer<HttpRequest> onApplyCallback) {
        this(owner, endpoint, null, null, targetBaseUrl, currentRawRequest, sessionStore, onApplyCallback);
    }

    private void initComponents() {
        JPanel contentPanel = new JPanel(new BorderLayout(8, 8));
        contentPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top Container: Info Banner & Collection Selector
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        // 1. Info Banner
        JPanel bannerPanel = new JPanel(new BorderLayout(4, 4));
        bannerPanel.setBackground(new Color(245, 247, 250));
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(210, 220, 230), 1),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JLabel titleLabel = new JLabel("Parameter Auto-Population and Configuration");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        JLabel descLabel = new JLabel("Parameters are auto-extracted matching Parameter Collector. Pre-filled values reflect the active request, while empty parameters can be filled and applied in-place.");
        descLabel.setFont(descLabel.getFont().deriveFont(Font.PLAIN, 11f));
        descLabel.setForeground(Color.DARK_GRAY);

        bannerPanel.add(titleLabel, BorderLayout.NORTH);
        bannerPanel.add(descLabel, BorderLayout.SOUTH);
        topContainer.add(bannerPanel);

        // 2. Collection Selector Toolbar (Matching Parameter Collector)
        JPanel collectionBar = new JPanel(new BorderLayout(8, 4));
        collectionBar.setBorder(new EmptyBorder(6, 2, 4, 2));

        JPanel leftColPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        leftColPanel.add(new JLabel("Collection:"));

        collectionSelector = new JComboBox<>();
        collectionSelector.setPreferredSize(new Dimension(280, 26));
        populateCollectionSelector();
        collectionSelector.addActionListener(e -> rebuildDialogTables());
        leftColPanel.add(collectionSelector);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.setToolTipText("Re-discover and synchronize parameters from the selected collection");
        refreshBtn.addActionListener(e -> rebuildDialogTables());
        leftColPanel.add(refreshBtn);

        collectionBar.add(leftColPanel, BorderLayout.WEST);
        topContainer.add(collectionBar);

        contentPanel.add(topContainer, BorderLayout.NORTH);

        tabbedPane = new JTabbedPane();

        // Initialize Table Models
        String[] columnNames = {"Parameter", "Type", "Status", "Value"};
        pathTableModel = createNonEditableNameTableModel(columnNames);
        queryTableModel = createNonEditableNameTableModel(columnNames);
        bodyTableModel = createNonEditableNameTableModel(columnNames);

        // 1. Path Parameters Tab
        JPanel pathPanel = createParameterSectionPanel("Path", pathTableModel);
        tabbedPane.addTab("Path", pathPanel);

        // 2. Query Parameters Tab
        JPanel queryPanel = createParameterSectionPanel("Query", queryTableModel);
        tabbedPane.addTab("Query", queryPanel);

        // 3. Body Parameters Tab
        JPanel bodyPanel = createParameterSectionPanel("Body", bodyTableModel);
        tabbedPane.addTab("Body", bodyPanel);

        contentPanel.add(tabbedPane, BorderLayout.CENTER);

        // Rebuild tables with collection-wide discovered parameters
        rebuildDialogTables();

        // Bottom Actions Bar
        JPanel bottomPanel = new JPanel(new BorderLayout());
        JPanel leftStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JLabel noteLabel = new JLabel("Tip: Double click any 'Value' cell to edit. Empty parameters are marked in amber.");
        noteLabel.setFont(noteLabel.getFont().deriveFont(Font.ITALIC, 11f));
        noteLabel.setForeground(Color.GRAY);
        leftStatusPanel.add(noteLabel);
        bottomPanel.add(leftStatusPanel, BorderLayout.WEST);

        JPanel rightActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton applyBtn = new JButton("Apply");
        applyBtn.setToolTipText("Apply parameter updates in-place to the request editor without closing this window");
        applyBtn.addActionListener(e -> applyParametersInPlace(false));

        JButton okBtn = new JButton("OK");
        okBtn.setToolTipText("Apply parameter updates in-place to the request editor and close this window");
        okBtn.addActionListener(e -> applyParametersInPlace(true));

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        rightActions.add(applyBtn);
        rightActions.add(okBtn);
        rightActions.add(cancelBtn);
        bottomPanel.add(rightActions, BorderLayout.EAST);

        contentPanel.add(bottomPanel, BorderLayout.SOUTH);
        setContentPane(contentPanel);
    }

    private void populateCollectionSelector() {
        collectionSelector.removeAllItems();
        collectionSelector.addItem(new CollectionComboItem(null, "[All Imported Collections]"));
        int selectedIndex = 0;
        for (int i = 0; i < allCollections.size(); i++) {
            ImportedCollection_littlespidy c = allCollections.get(i);
            collectionSelector.addItem(new CollectionComboItem(c, c.getName() + " (" + c.getEndpointCount() + ")"));
            if (initialCollection != null && initialCollection.getId() != null && initialCollection.getId().equals(c.getId())) {
                selectedIndex = i + 1; // 0 is [All Imported Collections]
            }
        }
        if (selectedIndex < collectionSelector.getItemCount()) {
            collectionSelector.setSelectedIndex(selectedIndex);
        }
    }

    private DefaultTableModel createNonEditableNameTableModel(String[] columnNames) {
        return new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 3 || column == 0;
            }
        };
    }

    /**
     * Rebuilds all parameter tables using Parameter Collector's collection-wide discovery algorithm.
     * Identifies active endpoint/request parameters and pre-fills them, while listing remaining
     * collection parameters as Empty so the user can easily see, fill, and apply them.
     */
    public synchronized void rebuildDialogTables() {
        if (pathTableModel == null || queryTableModel == null || bodyTableModel == null) {
            return;
        }

        // 1. Determine Target Collections
        List<ImportedCollection_littlespidy> targetCols = new ArrayList<>();
        CollectionComboItem sel = (collectionSelector != null) ? (CollectionComboItem) collectionSelector.getSelectedItem() : null;
        if (sel == null || sel.collection == null) {
            if (!allCollections.isEmpty()) {
                targetCols.addAll(allCollections);
            } else if (initialCollection != null) {
                targetCols.add(initialCollection);
            }
        } else {
            targetCols.add(sel.collection);
        }

        // 2. Discover collection-wide parameters matching Parameter Collector
        ParameterCollectorTab_littlespidy.DiscoveredParameters discovered =
                ParameterCollectorTab_littlespidy.collectParameters(targetCols);

        // 3. Inspect Active Endpoint & Live Request Parameters
        Map<String, String> activePathParams = new LinkedHashMap<>();
        Map<String, String> activePathTypes = new LinkedHashMap<>();
        if (endpoint != null && endpoint.getPathParams() != null) {
            for (Map.Entry<String, String> e : endpoint.getPathParams().entrySet()) {
                if (e.getKey() != null && !e.getKey().isBlank()) {
                    activePathParams.put(e.getKey().trim(), e.getValue() != null ? e.getValue() : "");
                }
            }
            if (endpoint.getPathParamTypes() != null) {
                activePathTypes.putAll(endpoint.getPathParamTypes());
            }
        }
        if (endpoint != null && endpoint.getPath() != null) {
            String cleanPath = endpoint.getPath().contains("?")
                    ? endpoint.getPath().substring(0, endpoint.getPath().indexOf('?'))
                    : endpoint.getPath();
            Matcher m = PATH_VARIABLE_PATTERN.matcher(cleanPath);
            while (m.find()) {
                String name = m.group(1) != null ? m.group(1) : m.group(2);
                if (name != null && !name.isBlank()) {
                    activePathParams.putIfAbsent(name.trim(), "");
                }
            }
        }
        String reqPath = extractPathFromRawRequest(currentRawRequest);
        if (reqPath != null && !reqPath.isBlank() && endpoint != null && endpoint.getPath() != null) {
            extractPathValuesFromLiveRequest(endpoint.getPath(), reqPath, activePathParams);
        }

        Map<String, String> activeQueryParams = new LinkedHashMap<>();
        Map<String, String> activeQueryTypes = new LinkedHashMap<>();
        if (endpoint != null && endpoint.getQueryParams() != null) {
            for (Map.Entry<String, String> e : endpoint.getQueryParams().entrySet()) {
                if (e.getKey() != null && !e.getKey().isBlank()) {
                    activeQueryParams.put(e.getKey().trim(), e.getValue() != null ? e.getValue() : "");
                }
            }
            if (endpoint.getQueryParamTypes() != null) {
                activeQueryTypes.putAll(endpoint.getQueryParamTypes());
            }
        }
        if (endpoint != null && endpoint.getPath() != null && endpoint.getPath().contains("?")) {
            parseQueryString(endpoint.getPath().substring(endpoint.getPath().indexOf('?') + 1), activeQueryParams);
        }
        if (reqPath != null && reqPath.contains("?")) {
            parseQueryString(reqPath.substring(reqPath.indexOf('?') + 1), activeQueryParams);
        }

        Map<String, String> activeBodyParams = new LinkedHashMap<>();
        Map<String, String> activeBodyTypes = new LinkedHashMap<>();
        if (endpoint != null && endpoint.getBodyParams() != null) {
            for (Map.Entry<String, String> e : endpoint.getBodyParams().entrySet()) {
                if (e.getKey() != null && !e.getKey().isBlank()) {
                    activeBodyParams.put(e.getKey().trim(), e.getValue() != null ? e.getValue() : "");
                }
            }
            if (endpoint.getBodyParamTypes() != null) {
                activeBodyTypes.putAll(endpoint.getBodyParamTypes());
            }
        }
        String bodyContent = extractBodyFromRawRequest(currentRawRequest);
        if (bodyContent == null || bodyContent.isBlank()) {
            bodyContent = (endpoint != null && endpoint.getRequestBodySample() != null) ? endpoint.getRequestBodySample() : "";
        }
        if (!bodyContent.isBlank()) {
            String trimmedBody = bodyContent.trim();
            if (trimmedBody.startsWith("{") || trimmedBody.startsWith("[")) {
                try {
                    JsonElement elem = JsonParser.parseString(trimmedBody);
                    extractJsonParamsRecursively(elem, "", activeBodyParams, activeBodyTypes);
                } catch (Exception ignored) {}
            } else if (trimmedBody.contains("=") && !trimmedBody.contains("\n")) {
                parseQueryString(trimmedBody, activeBodyParams);
            }
        }

        // Save original keys for accurate non-destructive mutation
        originalActivePathKeys.clear();
        originalActivePathKeys.addAll(activePathParams.keySet());
        originalActiveQueryKeys.clear();
        originalActiveQueryKeys.addAll(activeQueryParams.keySet());
        originalActiveBodyKeys.clear();
        originalActiveBodyKeys.addAll(activeBodyParams.keySet());

        // 4. Populate Path Table
        pathTableModel.setRowCount(0);
        Set<String> addedPath = new HashSet<>();
        for (Map.Entry<String, String> entry : activePathParams.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue() != null ? entry.getValue() : "";
            String type = activePathTypes.getOrDefault(name, inferType(val));
            String status = isValueEmptyOrPlaceholder(val) ? "Empty" : "Pre-filled";
            pathTableModel.addRow(new Object[]{name, type, status, val});
            addedPath.add(name);
        }
        for (Map.Entry<String, ParameterCollectorTab_littlespidy.ParameterEntry> pe : discovered.pathParams.entrySet()) {
            if (!addedPath.contains(pe.getKey())) {
                String name = pe.getKey();
                String type = pe.getValue().dataType != null ? pe.getValue().dataType : "string";
                pathTableModel.addRow(new Object[]{name, type, "Empty", ""});
                addedPath.add(name);
            }
        }

        // 5. Populate Query Table
        queryTableModel.setRowCount(0);
        Set<String> addedQuery = new HashSet<>();
        for (Map.Entry<String, String> entry : activeQueryParams.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue() != null ? entry.getValue() : "";
            String type = activeQueryTypes.getOrDefault(name, inferType(val));
            String status = isValueEmptyOrPlaceholder(val) ? "Empty" : "Pre-filled";
            queryTableModel.addRow(new Object[]{name, type, status, val});
            addedQuery.add(name);
        }
        for (Map.Entry<String, ParameterCollectorTab_littlespidy.ParameterEntry> pe : discovered.queryParams.entrySet()) {
            if (!addedQuery.contains(pe.getKey())) {
                String name = pe.getKey();
                String type = pe.getValue().dataType != null ? pe.getValue().dataType : "string";
                queryTableModel.addRow(new Object[]{name, type, "Empty", ""});
                addedQuery.add(name);
            }
        }

        // 6. Populate Body Table
        bodyTableModel.setRowCount(0);
        Set<String> addedBody = new HashSet<>();
        for (Map.Entry<String, String> entry : activeBodyParams.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue() != null ? entry.getValue() : "";
            String type = activeBodyTypes.getOrDefault(name, inferType(val));
            String status = isValueEmptyOrPlaceholder(val) ? "Empty" : "Pre-filled";
            bodyTableModel.addRow(new Object[]{name, type, status, val});
            addedBody.add(name);
        }
        for (Map.Entry<String, ParameterCollectorTab_littlespidy.ParameterEntry> pe : discovered.bodyParams.entrySet()) {
            if (!addedBody.contains(pe.getKey())) {
                String name = pe.getKey();
                String type = pe.getValue().dataType != null ? pe.getValue().dataType : "string";
                bodyTableModel.addRow(new Object[]{name, type, "Empty", ""});
                addedBody.add(name);
            }
        }

        updateAllTabTitles();
    }

    private String formatTabTitle(String section, DefaultTableModel model) {
        int total = model.getRowCount();
        int emptyCount = 0;
        for (int r = 0; r < total; r++) {
            Object status = model.getValueAt(r, 2);
            if ("Empty".equals(status)) {
                emptyCount++;
            }
        }
        if (emptyCount > 0) {
            return section + " (" + emptyCount + " empty, " + (total - emptyCount) + " filled)";
        }
        return section + " (" + total + ")";
    }

    private void updateAllTabTitles() {
        if (tabbedPane != null && tabbedPane.getTabCount() >= 3) {
            tabbedPane.setTitleAt(0, formatTabTitle("Path", pathTableModel));
            tabbedPane.setTitleAt(1, formatTabTitle("Query", queryTableModel));
            tabbedPane.setTitleAt(2, formatTabTitle("Body", bodyTableModel));
        }
    }

    private JPanel createParameterSectionPanel(String sectionName, DefaultTableModel tableModel) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // Sub-toolbar: Filter & Add/Remove
        JPanel topFilterBar = new JPanel(new BorderLayout(8, 4));
        JPanel leftFilter = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        leftFilter.add(new JLabel("Search:"));
        JTextField searchField = new JTextField(12);
        leftFilter.add(searchField);

        JCheckBox emptyOnlyCheck = new JCheckBox("Show Empty Only");
        leftFilter.add(emptyOnlyCheck);
        topFilterBar.add(leftFilter, BorderLayout.WEST);

        JPanel rightControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton addBtn = new JButton("Add Parameter");
        addBtn.addActionListener(e -> {
            String name = JOptionPane.showInputDialog(this, "Enter parameter name:", "Add " + sectionName + " Parameter", JOptionPane.PLAIN_MESSAGE);
            if (name != null && !name.trim().isEmpty()) {
                tableModel.addRow(new Object[]{name.trim(), "string", "Empty", ""});
                updateAllTabTitles();
            }
        });
        rightControls.add(addBtn);

        JButton removeBtn = new JButton("Remove Parameter");
        rightControls.add(removeBtn);
        topFilterBar.add(rightControls, BorderLayout.EAST);

        panel.add(topFilterBar, BorderLayout.NORTH);

        JTable table = new JTable(tableModel);
        table.setRowHeight(24);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        table.getColumnModel().getColumn(0).setPreferredWidth(170); // Name
        table.getColumnModel().getColumn(1).setPreferredWidth(85);  // Type
        table.getColumnModel().getColumn(2).setPreferredWidth(95);  // Status
        table.getColumnModel().getColumn(3).setPreferredWidth(320); // Value

        // Status column renderer (Amber for Empty, Green for Pre-filled)
        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, col);
                if (isSelected) return c;
                if ("Empty".equals(value)) {
                    c.setForeground(new Color(190, 80, 0));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("Pre-filled".equals(value)) {
                    c.setForeground(new Color(0, 130, 0));
                    c.setFont(c.getFont().deriveFont(Font.PLAIN));
                }
                return c;
            }
        });

        // Filter listener
        Runnable applyTableFilter = () -> {
            String text = searchField.getText().trim().toLowerCase(Locale.ROOT);
            boolean emptyOnly = emptyOnlyCheck.isSelected();
            sorter.setRowFilter(new RowFilter<>() {
                @Override
                public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                    int modelRow = entry.getIdentifier();
                    String param = String.valueOf(entry.getModel().getValueAt(modelRow, 0)).toLowerCase(Locale.ROOT);
                    String status = String.valueOf(entry.getModel().getValueAt(modelRow, 2));
                    String val = String.valueOf(entry.getModel().getValueAt(modelRow, 3)).toLowerCase(Locale.ROOT);

                    if (emptyOnly && !"Empty".equals(status)) {
                        return false;
                    }
                    if (!text.isEmpty()) {
                        return param.contains(text) || val.contains(text);
                    }
                    return true;
                }
            });
        };

        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyTableFilter.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyTableFilter.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyTableFilter.run(); }
        });
        emptyOnlyCheck.addActionListener(e -> applyTableFilter.run());

        removeBtn.addActionListener(e -> {
            int selected = table.getSelectedRow();
            if (selected >= 0) {
                int modelIdx = table.convertRowIndexToModel(selected);
                tableModel.removeRow(modelIdx);
                updateAllTabTitles();
            }
        });

        tableModel.addTableModelListener(e -> {
            if (e.getColumn() == 3) { // Value edited
                int r = e.getFirstRow();
                if (r >= 0 && r < tableModel.getRowCount()) {
                    Object valObj = tableModel.getValueAt(r, 3);
                    String valStr = valObj != null ? valObj.toString().trim() : "";
                    String newStatus = isValueEmptyOrPlaceholder(valStr) ? "Empty" : "Pre-filled";
                    if (!newStatus.equals(tableModel.getValueAt(r, 2))) {
                        SwingUtilities.invokeLater(() -> {
                            tableModel.setValueAt(newStatus, r, 2);
                            updateAllTabTitles();
                        });
                    }
                }
            }
        });

        if ("Path".equals(sectionName)) {
            pathTable = table;
            pathSorter = sorter;
            pathEmptyOnlyCheck = emptyOnlyCheck;
        } else if ("Query".equals(sectionName)) {
            queryTable = table;
            querySorter = sorter;
            queryEmptyOnlyCheck = emptyOnlyCheck;
        } else if ("Body".equals(sectionName)) {
            bodyTable = table;
            bodySorter = sorter;
            bodyEmptyOnlyCheck = emptyOnlyCheck;
        }

        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private static boolean isValueEmptyOrPlaceholder(String val) {
        if (val == null || val.isBlank()) return true;
        String t = val.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith(":") && t.length() > 1);
    }

    private void extractJsonParamsRecursively(JsonElement elem, String prefix, Map<String, String> outParams, Map<String, String> outTypes) {
        if (elem == null || elem.isJsonNull()) return;

        if (elem.isJsonObject()) {
            JsonObject obj = elem.getAsJsonObject();
            for (Map.Entry<String, JsonElement> e : obj.entrySet()) {
                String key = e.getKey();
                String fullPath = prefix.isEmpty() ? key : prefix + "." + key;
                JsonElement v = e.getValue();
                if (v.isJsonPrimitive()) {
                    outParams.put(fullPath, v.getAsString());
                    outTypes.put(fullPath, inferPrimitiveType(v.getAsJsonPrimitive()));
                } else if (v.isJsonObject()) {
                    extractJsonParamsRecursively(v, fullPath, outParams, outTypes);
                } else if (v.isJsonArray()) {
                    outParams.put(fullPath, GSON.toJson(v));
                    outTypes.put(fullPath, "array");
                }
            }
        } else if (elem.isJsonPrimitive()) {
            if (!prefix.isEmpty()) {
                outParams.put(prefix, elem.getAsString());
                outTypes.put(prefix, inferPrimitiveType(elem.getAsJsonPrimitive()));
            }
        }
    }

    private String inferPrimitiveType(JsonPrimitive p) {
        if (p.isBoolean()) return "boolean";
        if (p.isNumber()) return "number";
        return "string";
    }

    private String inferType(String val) {
        if (val == null || val.isBlank()) return "string";
        String t = val.trim();
        if ("true".equalsIgnoreCase(t) || "false".equalsIgnoreCase(t)) return "boolean";
        try {
            Double.parseDouble(t);
            return "number";
        } catch (NumberFormatException e) {
            return "string";
        }
    }

    private void parseQueryString(String qStr, Map<String, String> targetMap) {
        if (qStr == null || qStr.isBlank()) return;
        String[] pairs = qStr.split("&");
        for (String pair : pairs) {
            if (!pair.isBlank()) {
                int eq = pair.indexOf('=');
                String k = eq > 0 ? pair.substring(0, eq).trim() : pair.trim();
                String v = eq > 0 && eq < pair.length() - 1 ? pair.substring(eq + 1).trim() : "";
                if (!k.isBlank()) {
                    targetMap.put(k, v);
                }
            }
        }
    }

    private String extractPathFromRawRequest(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String[] lines = raw.split("(\\r\\n|\\n)");
        if (lines.length > 0) {
            String[] tokens = lines[0].trim().split("\\s+");
            if (tokens.length > 1) {
                return tokens[1];
            }
        }
        return null;
    }

    private String extractBodyFromRawRequest(String raw) {
        if (raw == null || raw.isBlank()) return "";
        String[] parts = raw.split("(\\r\\n\\r\\n|\\n\\n)", 2);
        return parts.length > 1 ? parts[1] : "";
    }

    private void extractPathValuesFromLiveRequest(String templatePath, String livePath, Map<String, String> pathParams) {
        String cleanTemplate = templatePath.contains("?") ? templatePath.substring(0, templatePath.indexOf('?')) : templatePath;
        String cleanLive = livePath.contains("?") ? livePath.substring(0, livePath.indexOf('?')) : livePath;

        String[] tSegs = cleanTemplate.split("/");
        String[] lSegs = cleanLive.split("/");
        if (tSegs.length == lSegs.length) {
            for (int i = 0; i < tSegs.length; i++) {
                String t = tSegs[i];
                if ((t.startsWith("{") && t.endsWith("}")) || t.startsWith(":")) {
                    String paramName = t.startsWith("{") ? t.substring(1, t.length() - 1) : t.substring(1);
                    String liveVal = lSegs[i];
                    if (!liveVal.isBlank() && !liveVal.equals(t)) {
                        pathParams.put(paramName, liveVal);
                    }
                }
            }
        }
    }

    private void stopCellEditing(JTable table) {
        if (table != null && table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
    }

    /**
     * Applies parameter edits in-place to the HTTP request without destroying custom headers,
     * session tokens, or nested JSON structures.
     */
    private void applyParametersInPlace(boolean closeOnSuccess) {
        if (endpoint == null) return;

        stopCellEditing(pathTable);
        stopCellEditing(queryTable);
        stopCellEditing(bodyTable);

        // 1. Gather Path Updates
        Map<String, String> updatedPath = new LinkedHashMap<>();
        for (int r = 0; r < pathTableModel.getRowCount(); r++) {
            Object k = pathTableModel.getValueAt(r, 0);
            Object v = pathTableModel.getValueAt(r, 3);
            if (k != null && !k.toString().trim().isEmpty()) {
                String valStr = v != null ? v.toString().trim() : "";
                if (!valStr.isEmpty() || originalActivePathKeys.contains(k.toString().trim())) {
                    updatedPath.put(k.toString().trim(), valStr);
                }
            }
        }
        endpoint.setPathParams(updatedPath);

        // 2. Gather Query Updates
        Map<String, String> updatedQuery = new LinkedHashMap<>();
        for (int r = 0; r < queryTableModel.getRowCount(); r++) {
            Object k = queryTableModel.getValueAt(r, 0);
            Object v = queryTableModel.getValueAt(r, 3);
            if (k != null && !k.toString().trim().isEmpty()) {
                String valStr = v != null ? v.toString().trim() : "";
                if (!valStr.isEmpty() || originalActiveQueryKeys.contains(k.toString().trim())) {
                    updatedQuery.put(k.toString().trim(), valStr);
                }
            }
        }
        endpoint.setQueryParams(updatedQuery);

        // 3. Gather Body Updates
        Map<String, String> updatedBody = new LinkedHashMap<>();
        for (int r = 0; r < bodyTableModel.getRowCount(); r++) {
            Object k = bodyTableModel.getValueAt(r, 0);
            Object v = bodyTableModel.getValueAt(r, 3);
            if (k != null && !k.toString().trim().isEmpty()) {
                String valStr = v != null ? v.toString().trim() : "";
                if (!valStr.isEmpty() || originalActiveBodyKeys.contains(k.toString().trim())) {
                    updatedBody.put(k.toString().trim(), valStr);
                }
            }
        }
        endpoint.setBodyParams(updatedBody);

        // 4. Non-Destructive In-Place Request Mutator
        String baseRaw = (currentRawRequest != null && !currentRawRequest.isBlank())
                ? currentRawRequest
                : (endpoint.hasCustomRequest() ? endpoint.getCustomRawRequest() : null);

        if (baseRaw == null || baseRaw.isBlank()) {
            HttpRequest baseline = AuthTestEngine_littlespidy.buildDefaultRequest(targetBaseUrl, endpoint);
            if (baseline != null && baseline.toByteArray() != null) {
                baseRaw = new String(baseline.toByteArray().getBytes(), StandardCharsets.UTF_8);
            } else {
                baseRaw = "GET " + endpoint.getPath() + " HTTP/1.1\r\nHost: localhost\r\n\r\n";
            }
        }

        String mutatedRaw = mutateRequestInPlace(baseRaw, updatedPath, updatedQuery, updatedBody);
        currentRawRequest = mutatedRaw;
        endpoint.setCustomRawRequest(mutatedRaw);

        HttpRequest finalReq = AuthTestEngine_littlespidy.buildFromCustomRequest(targetBaseUrl, mutatedRaw);
        if (sessionStore != null && sessionStore.appliesTo(endpoint)) {
            finalReq = sessionStore.applyToRequest(finalReq, endpoint);
        }

        if (onApplyCallback != null) {
            onApplyCallback.accept(finalReq);
        }

        updateAllTabTitles();

        if (closeOnSuccess) {
            dispose();
        }
    }

    private String mutateRequestInPlace(
            String raw,
            Map<String, String> pathParams,
            Map<String, String> queryParams,
            Map<String, String> bodyParams) {

        String[] headerAndBody = raw.split("(\\r\\n\\r\\n|\\n\\n)", 2);
        String headerSection = headerAndBody[0];
        String bodySection = headerAndBody.length > 1 ? headerAndBody[1] : "";

        String[] headerLines = headerSection.split("(\\r\\n|\\n)");
        if (headerLines.length == 0) return raw;

        String requestLine = headerLines[0].trim();
        String[] tokens = requestLine.split("\\s+");
        String method = tokens.length > 0 ? tokens[0] : "GET";
        String path = tokens.length > 1 ? tokens[1] : "/";
        String httpVersion = tokens.length > 2 ? tokens[2] : "HTTP/1.1";

        // Separate path & existing query
        String cleanPath = path;
        String queryStr = "";
        int qIdx = path.indexOf('?');
        if (qIdx >= 0) {
            cleanPath = path.substring(0, qIdx);
            queryStr = path.substring(qIdx + 1);
        }

        // In-place Path Variable Replacement
        for (Map.Entry<String, String> p : pathParams.entrySet()) {
            String key = p.getKey();
            String val = p.getValue();
            if (!val.isEmpty()) {
                cleanPath = cleanPath.replace("{" + key + "}", val);
                cleanPath = cleanPath.replace(":" + key, val);
            }
        }

        // In-place Query Parameters Update
        Map<String, String> existingQueryMap = new LinkedHashMap<>();
        parseQueryString(queryStr, existingQueryMap);
        for (Map.Entry<String, String> q : queryParams.entrySet()) {
            if (!q.getValue().isEmpty() || existingQueryMap.containsKey(q.getKey())) {
                existingQueryMap.put(q.getKey(), q.getValue());
            }
        }

        StringBuilder newQuery = new StringBuilder();
        for (Map.Entry<String, String> q : existingQueryMap.entrySet()) {
            if (newQuery.length() > 0) newQuery.append("&");
            newQuery.append(q.getKey());
            if (q.getValue() != null && !q.getValue().isEmpty()) {
                newQuery.append("=").append(q.getValue());
            }
        }

        String newPath = cleanPath;
        if (newQuery.length() > 0) {
            newPath += "?" + newQuery;
        }

        // In-place Body Parameters Update (Preserves nested JSON & untouched fields)
        String newBody = bodySection;
        if (!bodyParams.isEmpty()) {
            String trimmedBody = bodySection.trim();
            if (trimmedBody.startsWith("{")) {
                try {
                    JsonElement rootEl = JsonParser.parseString(trimmedBody);
                    if (rootEl.isJsonObject()) {
                        JsonObject rootObj = rootEl.getAsJsonObject();
                        for (Map.Entry<String, String> b : bodyParams.entrySet()) {
                            if (!b.getValue().isEmpty() || originalActiveBodyKeys.contains(b.getKey())) {
                                setJsonFieldByPath(rootObj, b.getKey(), b.getValue());
                            }
                        }
                        newBody = GSON.toJson(rootObj);
                    }
                } catch (Exception ignored) {
                    newBody = bodySection;
                }
            } else if (trimmedBody.contains("=") && !trimmedBody.contains("\n")) {
                Map<String, String> formMap = new LinkedHashMap<>();
                parseQueryString(trimmedBody, formMap);
                for (Map.Entry<String, String> b : bodyParams.entrySet()) {
                    if (!b.getValue().isEmpty() || originalActiveBodyKeys.contains(b.getKey())) {
                        formMap.put(b.getKey(), b.getValue());
                    }
                }
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, String> f : formMap.entrySet()) {
                    if (sb.length() > 0) sb.append("&");
                    sb.append(f.getKey()).append("=").append(f.getValue());
                }
                newBody = sb.toString();
            } else if (trimmedBody.isEmpty()) {
                JsonObject newObj = new JsonObject();
                for (Map.Entry<String, String> b : bodyParams.entrySet()) {
                    if (!b.getValue().isEmpty()) {
                        setJsonFieldByPath(newObj, b.getKey(), b.getValue());
                    }
                }
                if (newObj.keySet().isEmpty()) {
                    newBody = "";
                } else {
                    newBody = GSON.toJson(newObj);
                }
            }
        }

        // Assemble headers with updated Request Line and accurate Content-Length
        List<String> newHeaderLines = new ArrayList<>();
        newHeaderLines.add(method + " " + newPath + " " + httpVersion);

        int bodyLen = newBody.getBytes(StandardCharsets.UTF_8).length;
        boolean hasContentLength = false;

        for (int i = 1; i < headerLines.length; i++) {
            String line = headerLines[i];
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                if (bodyLen > 0 || "POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
                    newHeaderLines.add("Content-Length: " + bodyLen);
                    hasContentLength = true;
                }
            } else {
                newHeaderLines.add(line);
            }
        }

        if (!hasContentLength && bodyLen > 0) {
            newHeaderLines.add("Content-Length: " + bodyLen);
        }

        return String.join("\r\n", newHeaderLines) + "\r\n\r\n" + newBody;
    }

    private void setJsonFieldByPath(JsonObject root, String path, String val) {
        String[] parts = path.split("\\.");
        JsonObject current = root;
        for (int i = 0; i < parts.length - 1; i++) {
            String p = parts[i];
            if (current.has(p) && current.get(p).isJsonObject()) {
                current = current.getAsJsonObject(p);
            } else {
                JsonObject next = new JsonObject();
                current.add(p, next);
                current = next;
            }
        }
        String leaf = parts[parts.length - 1];
        if (val == null || val.isBlank()) {
            current.addProperty(leaf, "");
        } else if ("true".equalsIgnoreCase(val) || "false".equalsIgnoreCase(val)) {
            current.addProperty(leaf, Boolean.parseBoolean(val));
        } else {
            try {
                if (val.contains(".")) {
                    current.addProperty(leaf, Double.parseDouble(val));
                } else {
                    current.addProperty(leaf, Long.parseLong(val));
                }
            } catch (NumberFormatException e) {
                current.addProperty(leaf, val);
            }
        }
    }

    public DefaultTableModel getPathTableModel() {
        return pathTableModel;
    }

    public DefaultTableModel getQueryTableModel() {
        return queryTableModel;
    }

    public DefaultTableModel getBodyTableModel() {
        return bodyTableModel;
    }

    public static class CollectionComboItem {
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
