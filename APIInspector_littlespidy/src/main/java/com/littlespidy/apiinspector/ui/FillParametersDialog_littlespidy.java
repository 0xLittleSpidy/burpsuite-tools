// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
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
 * Employs comprehensive auto-population (matching Parameter Collector discovery), visual
 * identification of empty vs pre-filled values, and non-destructive in-place request modification
 * to preserve custom headers, authentication tokens, and nested JSON structures.
 */
public class FillParametersDialog_littlespidy extends JDialog {

    private static final Pattern PATH_VARIABLE_PATTERN = Pattern.compile("\\{([a-zA-Z0-9_\\-]+)\\}|:([a-zA-Z0-9_\\-]+)");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final DiscoveredEndpoint_littlespidy endpoint;
    private final String targetBaseUrl;
    private String currentRawRequest;
    private final SessionStore_littlespidy sessionStore;
    private final Consumer<HttpRequest> onApplyCallback;

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

    public FillParametersDialog_littlespidy(
            Window owner,
            DiscoveredEndpoint_littlespidy endpoint,
            String targetBaseUrl,
            String currentRawRequest,
            SessionStore_littlespidy sessionStore,
            Consumer<HttpRequest> onApplyCallback) {
        super(owner, "Fill Parameters - " + (endpoint != null ? endpoint.getMethod() + " " + endpoint.getPath() : ""), ModalityType.MODELESS);
        this.endpoint = endpoint;
        this.targetBaseUrl = targetBaseUrl != null && !targetBaseUrl.isBlank() ? targetBaseUrl : "https://localhost";
        this.currentRawRequest = (currentRawRequest != null && !currentRawRequest.isBlank())
                ? currentRawRequest
                : (endpoint != null && endpoint.hasCustomRequest() ? endpoint.getCustomRawRequest() : "");
        this.sessionStore = sessionStore;
        this.onApplyCallback = onApplyCallback;

        initComponents();
        setSize(760, 520);
        setLocationRelativeTo(owner);
    }

    private void initComponents() {
        JPanel contentPanel = new JPanel(new BorderLayout(8, 8));
        contentPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Info Banner
        JPanel bannerPanel = new JPanel(new BorderLayout(4, 4));
        bannerPanel.setBackground(new Color(245, 247, 250));
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(210, 220, 230), 1),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JLabel titleLabel = new JLabel("Parameter Auto-Population and Configuration");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        JLabel descLabel = new JLabel("Parameters are auto-extracted from spec templates and active requests. Edit values below; changes apply in-place preserving custom headers and JSON structure.");
        descLabel.setFont(descLabel.getFont().deriveFont(Font.PLAIN, 11f));
        descLabel.setForeground(Color.DARK_GRAY);

        bannerPanel.add(titleLabel, BorderLayout.NORTH);
        bannerPanel.add(descLabel, BorderLayout.SOUTH);
        contentPanel.add(bannerPanel, BorderLayout.NORTH);

        tabbedPane = new JTabbedPane();

        // 1. Path Parameters Tab
        JPanel pathPanel = createParameterSectionPanel("Path", createPathTableModel());
        tabbedPane.addTab(formatTabTitle("Path", pathTableModel), pathPanel);

        // 2. Query Parameters Tab
        JPanel queryPanel = createParameterSectionPanel("Query", createQueryTableModel());
        tabbedPane.addTab(formatTabTitle("Query", queryTableModel), queryPanel);

        // 3. Body Parameters Tab
        JPanel bodyPanel = createParameterSectionPanel("Body", createBodyTableModel());
        tabbedPane.addTab(formatTabTitle("Body", bodyTableModel), bodyPanel);

        contentPanel.add(tabbedPane, BorderLayout.CENTER);

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

    private DefaultTableModel createPathTableModel() {
        String[] columnNames = {"Parameter", "Type", "Status", "Value"};
        pathTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 3 || column == 0;
            }
        };

        Map<String, String> pathParams = new LinkedHashMap<>();
        Map<String, String> pathTypes = new LinkedHashMap<>();

        // 1. From endpoint pathParams map
        if (endpoint != null && endpoint.getPathParams() != null) {
            for (Map.Entry<String, String> e : endpoint.getPathParams().entrySet()) {
                if (e.getKey() != null && !e.getKey().isBlank()) {
                    pathParams.put(e.getKey().trim(), e.getValue() != null ? e.getValue() : "");
                }
            }
            if (endpoint.getPathParamTypes() != null) {
                pathTypes.putAll(endpoint.getPathParamTypes());
            }
        }

        // 2. Discover from endpoint.getPath() using PATH_VARIABLE_PATTERN
        if (endpoint != null && endpoint.getPath() != null) {
            String cleanPath = endpoint.getPath().contains("?")
                    ? endpoint.getPath().substring(0, endpoint.getPath().indexOf('?'))
                    : endpoint.getPath();
            Matcher m = PATH_VARIABLE_PATTERN.matcher(cleanPath);
            while (m.find()) {
                String name = m.group(1) != null ? m.group(1) : m.group(2);
                if (name != null && !name.isBlank()) {
                    name = name.trim();
                    if (!pathParams.containsKey(name)) {
                        pathParams.put(name, "");
                    }
                }
            }
        }

        // 3. Inspect active request URI path to extract existing filled values
        String reqPath = extractPathFromRawRequest(currentRawRequest);
        if (reqPath != null && !reqPath.isBlank() && endpoint != null && endpoint.getPath() != null) {
            extractPathValuesFromLiveRequest(endpoint.getPath(), reqPath, pathParams);
        }

        for (Map.Entry<String, String> entry : pathParams.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue();
            String type = pathTypes.getOrDefault(name, inferType(val));
            String status = isValueEmptyOrPlaceholder(val) ? "Empty" : "Pre-filled";
            pathTableModel.addRow(new Object[]{name, type, status, val});
        }
        return pathTableModel;
    }

    private DefaultTableModel createQueryTableModel() {
        String[] columnNames = {"Parameter", "Type", "Status", "Value"};
        queryTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 3 || column == 0;
            }
        };

        Map<String, String> queryParams = new LinkedHashMap<>();
        Map<String, String> queryTypes = new LinkedHashMap<>();

        // 1. From endpoint queryParams map
        if (endpoint != null && endpoint.getQueryParams() != null) {
            for (Map.Entry<String, String> e : endpoint.getQueryParams().entrySet()) {
                if (e.getKey() != null && !e.getKey().isBlank()) {
                    queryParams.put(e.getKey().trim(), e.getValue() != null ? e.getValue() : "");
                }
            }
            if (endpoint.getQueryParamTypes() != null) {
                queryTypes.putAll(endpoint.getQueryParamTypes());
            }
        }

        // 2. From query string in endpoint.getPath()
        if (endpoint != null && endpoint.getPath() != null && endpoint.getPath().contains("?")) {
            parseQueryString(endpoint.getPath().substring(endpoint.getPath().indexOf('?') + 1), queryParams);
        }

        // 3. From current request URL query string
        String reqPath = extractPathFromRawRequest(currentRawRequest);
        if (reqPath != null && reqPath.contains("?")) {
            parseQueryString(reqPath.substring(reqPath.indexOf('?') + 1), queryParams);
        }

        for (Map.Entry<String, String> entry : queryParams.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue();
            String type = queryTypes.getOrDefault(name, inferType(val));
            String status = isValueEmptyOrPlaceholder(val) ? "Empty" : "Pre-filled";
            queryTableModel.addRow(new Object[]{name, type, status, val});
        }
        return queryTableModel;
    }

    private DefaultTableModel createBodyTableModel() {
        String[] columnNames = {"Parameter", "Type", "Status", "Value"};
        bodyTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 3 || column == 0;
            }
        };

        Map<String, String> bodyParams = new LinkedHashMap<>();
        Map<String, String> bodyTypes = new LinkedHashMap<>();

        // 1. From endpoint bodyParams map
        if (endpoint != null && endpoint.getBodyParams() != null) {
            for (Map.Entry<String, String> e : endpoint.getBodyParams().entrySet()) {
                if (e.getKey() != null && !e.getKey().isBlank()) {
                    bodyParams.put(e.getKey().trim(), e.getValue() != null ? e.getValue() : "");
                }
            }
            if (endpoint.getBodyParamTypes() != null) {
                bodyTypes.putAll(endpoint.getBodyParamTypes());
            }
        }

        // 2. Parse from live request body or requestBodySample via Gson
        String bodyContent = extractBodyFromRawRequest(currentRawRequest);
        if (bodyContent == null || bodyContent.isBlank()) {
            bodyContent = (endpoint != null && endpoint.getRequestBodySample() != null) ? endpoint.getRequestBodySample() : "";
        }

        if (!bodyContent.isBlank()) {
            String trimmedBody = bodyContent.trim();
            if (trimmedBody.startsWith("{") || trimmedBody.startsWith("[")) {
                try {
                    JsonElement elem = JsonParser.parseString(trimmedBody);
                    extractJsonParamsRecursively(elem, "", bodyParams, bodyTypes);
                } catch (Exception ignored) {}
            } else if (trimmedBody.contains("=") && !trimmedBody.contains("\n")) {
                parseQueryString(trimmedBody, bodyParams);
            }
        }

        for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue();
            String type = bodyTypes.getOrDefault(name, inferType(val));
            String status = isValueEmptyOrPlaceholder(val) ? "Empty" : "Pre-filled";
            bodyTableModel.addRow(new Object[]{name, type, status, val});
        }
        return bodyTableModel;
    }

    private void extractJsonParamsRecursively(
            JsonElement elem,
            String prefix,
            Map<String, String> outParams,
            Map<String, String> outTypes) {
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
                updatedPath.put(k.toString().trim(), v != null ? v.toString().trim() : "");
            }
        }
        endpoint.setPathParams(updatedPath);

        // 2. Gather Query Updates
        Map<String, String> updatedQuery = new LinkedHashMap<>();
        for (int r = 0; r < queryTableModel.getRowCount(); r++) {
            Object k = queryTableModel.getValueAt(r, 0);
            Object v = queryTableModel.getValueAt(r, 3);
            if (k != null && !k.toString().trim().isEmpty()) {
                updatedQuery.put(k.toString().trim(), v != null ? v.toString().trim() : "");
            }
        }
        endpoint.setQueryParams(updatedQuery);

        // 3. Gather Body Updates
        Map<String, String> updatedBody = new LinkedHashMap<>();
        for (int r = 0; r < bodyTableModel.getRowCount(); r++) {
            Object k = bodyTableModel.getValueAt(r, 0);
            Object v = bodyTableModel.getValueAt(r, 3);
            if (k != null && !k.toString().trim().isEmpty()) {
                updatedBody.put(k.toString().trim(), v != null ? v.toString().trim() : "");
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
        existingQueryMap.putAll(queryParams);

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
                            setJsonFieldByPath(rootObj, b.getKey(), b.getValue());
                        }
                        newBody = GSON.toJson(rootObj);
                    }
                } catch (Exception ignored) {
                    newBody = bodySection;
                }
            } else if (trimmedBody.contains("=") && !trimmedBody.contains("\n")) {
                Map<String, String> formMap = new LinkedHashMap<>();
                parseQueryString(trimmedBody, formMap);
                formMap.putAll(bodyParams);
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, String> f : formMap.entrySet()) {
                    if (sb.length() > 0) sb.append("&");
                    sb.append(f.getKey()).append("=").append(f.getValue());
                }
                newBody = sb.toString();
            } else if (trimmedBody.isEmpty()) {
                JsonObject newObj = new JsonObject();
                for (Map.Entry<String, String> b : bodyParams.entrySet()) {
                    setJsonFieldByPath(newObj, b.getKey(), b.getValue());
                }
                newBody = GSON.toJson(newObj);
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
}
