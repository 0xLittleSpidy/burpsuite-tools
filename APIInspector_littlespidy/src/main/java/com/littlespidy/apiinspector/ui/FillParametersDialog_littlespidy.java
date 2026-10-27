// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.SessionStore_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Dedicated dialog providing structured editing of Path, Query, and Body parameters
 * extracted from imported OpenAPI, Swagger, or Postman specifications.
 * Edits synchronize directly into the endpoint model and active HTTP Request Editor.
 */
public class FillParametersDialog_littlespidy extends JDialog {

    private final DiscoveredEndpoint_littlespidy endpoint;
    private final String targetBaseUrl;
    private final SessionStore_littlespidy sessionStore;
    private final Consumer<HttpRequest> onApplyCallback;

    private DefaultTableModel pathTableModel;
    private DefaultTableModel queryTableModel;
    private DefaultTableModel bodyTableModel;

    private JTable pathTable;
    private JTable queryTable;
    private JTable bodyTable;

    public FillParametersDialog_littlespidy(
            Window owner,
            DiscoveredEndpoint_littlespidy endpoint,
            String targetBaseUrl,
            SessionStore_littlespidy sessionStore,
            Consumer<HttpRequest> onApplyCallback) {
        super(owner, "Fill Parameters - " + (endpoint != null ? endpoint.getMethod() + " " + endpoint.getPath() : ""), ModalityType.APPLICATION_MODAL);
        this.endpoint = endpoint;
        this.targetBaseUrl = targetBaseUrl != null && !targetBaseUrl.isBlank() ? targetBaseUrl : "https://localhost";
        this.sessionStore = sessionStore;
        this.onApplyCallback = onApplyCallback;

        initComponents();
        setSize(680, 480);
        setLocationRelativeTo(owner);
    }

    private void initComponents() {
        JPanel contentPanel = new JPanel(new BorderLayout(8, 8));
        contentPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        // Info Banner
        JPanel bannerPanel = new JPanel(new BorderLayout(4, 4));
        bannerPanel.setBackground(new Color(245, 247, 250));
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(210, 220, 230), 1),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JLabel titleLabel = new JLabel("Parameter Value Configuration");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        JLabel descLabel = new JLabel("Edit parameter values below. Click 'Apply' or 'OK' to synchronize values into the HTTP Request.");
        descLabel.setFont(descLabel.getFont().deriveFont(Font.PLAIN, 11f));
        descLabel.setForeground(Color.DARK_GRAY);

        bannerPanel.add(titleLabel, BorderLayout.NORTH);
        bannerPanel.add(descLabel, BorderLayout.SOUTH);
        contentPanel.add(bannerPanel, BorderLayout.NORTH);

        // Tabbed Pane for Path, Query, Body sections
        JTabbedPane tabbedPane = new JTabbedPane();

        // 1. Path Parameters Tab
        JPanel pathPanel = createParameterSectionPanel("Path", createPathTableModel());
        tabbedPane.addTab("Path Parameters (" + pathTableModel.getRowCount() + ")", pathPanel);

        // 2. Query Parameters Tab
        JPanel queryPanel = createParameterSectionPanel("Query", createQueryTableModel());
        tabbedPane.addTab("Query Parameters (" + queryTableModel.getRowCount() + ")", queryPanel);

        // 3. Body Parameters Tab
        JPanel bodyPanel = createParameterSectionPanel("Body", createBodyTableModel());
        tabbedPane.addTab("Body Parameters (" + bodyTableModel.getRowCount() + ")", bodyPanel);

        contentPanel.add(tabbedPane, BorderLayout.CENTER);

        // Bottom Actions Bar
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton applyBtn = new JButton("Apply");
        applyBtn.setToolTipText("Apply parameter values to the request editor and keep this dialog open");
        applyBtn.addActionListener(e -> applyParameters(false));

        JButton okBtn = new JButton("OK");
        okBtn.setToolTipText("Apply parameter values to the request editor and close dialog");
        okBtn.addActionListener(e -> applyParameters(true));

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        bottomPanel.add(applyBtn);
        bottomPanel.add(okBtn);
        bottomPanel.add(cancelBtn);

        contentPanel.add(bottomPanel, BorderLayout.SOUTH);
        setContentPane(contentPanel);
    }

    private JPanel createParameterSectionPanel(String sectionName, DefaultTableModel tableModel) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        JTable table = new JTable(tableModel);
        table.setRowHeight(24);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(160);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(320);

        if ("Path".equals(sectionName)) pathTable = table;
        else if ("Query".equals(sectionName)) queryTable = table;
        else if ("Body".equals(sectionName)) bodyTable = table;

        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton addBtn = new JButton("Add Parameter");
        addBtn.addActionListener(e -> {
            String name = JOptionPane.showInputDialog(this, "Enter parameter name:", "Add " + sectionName + " Parameter", JOptionPane.PLAIN_MESSAGE);
            if (name != null && !name.trim().isEmpty()) {
                tableModel.addRow(new Object[]{name.trim(), "string", ""});
            }
        });
        toolbar.add(addBtn);

        JButton removeBtn = new JButton("Remove Parameter");
        removeBtn.addActionListener(e -> {
            int selected = table.getSelectedRow();
            if (selected >= 0) {
                tableModel.removeRow(selected);
            }
        });
        toolbar.add(removeBtn);

        panel.add(toolbar, BorderLayout.SOUTH);
        return panel;
    }

    private DefaultTableModel createPathTableModel() {
        String[] columnNames = {"Parameter", "Type", "Value"};
        pathTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2 || column == 0;
            }
        };

        if (endpoint != null && endpoint.getPathParams() != null) {
            Map<String, String> types = endpoint.getPathParamTypes() != null ? endpoint.getPathParamTypes() : Collections.emptyMap();
            for (Map.Entry<String, String> entry : endpoint.getPathParams().entrySet()) {
                String key = entry.getKey();
                String val = entry.getValue() != null ? entry.getValue() : "";
                String type = types.getOrDefault(key, "string");
                pathTableModel.addRow(new Object[]{key, type, val});
            }
        }
        return pathTableModel;
    }

    private DefaultTableModel createQueryTableModel() {
        String[] columnNames = {"Parameter", "Type", "Value"};
        queryTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2 || column == 0;
            }
        };

        if (endpoint != null && endpoint.getQueryParams() != null) {
            Map<String, String> types = endpoint.getQueryParamTypes() != null ? endpoint.getQueryParamTypes() : Collections.emptyMap();
            for (Map.Entry<String, String> entry : endpoint.getQueryParams().entrySet()) {
                String key = entry.getKey();
                String val = entry.getValue() != null ? entry.getValue() : "";
                String type = types.getOrDefault(key, "string");
                queryTableModel.addRow(new Object[]{key, type, val});
            }
        }
        return queryTableModel;
    }

    private DefaultTableModel createBodyTableModel() {
        String[] columnNames = {"Parameter", "Type", "Value"};
        bodyTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2 || column == 0;
            }
        };

        if (endpoint != null && endpoint.getBodyParams() != null) {
            Map<String, String> types = endpoint.getBodyParamTypes() != null ? endpoint.getBodyParamTypes() : Collections.emptyMap();
            for (Map.Entry<String, String> entry : endpoint.getBodyParams().entrySet()) {
                String key = entry.getKey();
                String val = entry.getValue() != null ? entry.getValue() : "";
                String type = types.getOrDefault(key, "string");
                bodyTableModel.addRow(new Object[]{key, type, val});
            }
        }
        return bodyTableModel;
    }

    private void stopCellEditing(JTable table) {
        if (table != null && table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
    }

    private void applyParameters(boolean closeOnSuccess) {
        if (endpoint == null) return;

        stopCellEditing(pathTable);
        stopCellEditing(queryTable);
        stopCellEditing(bodyTable);

        // 1. Sync Path Parameters
        Map<String, String> updatedPathParams = new LinkedHashMap<>();
        for (int r = 0; r < pathTableModel.getRowCount(); r++) {
            Object k = pathTableModel.getValueAt(r, 0);
            Object v = pathTableModel.getValueAt(r, 2);
            if (k != null && !k.toString().trim().isEmpty()) {
                updatedPathParams.put(k.toString().trim(), v != null ? v.toString() : "");
            }
        }
        endpoint.setPathParams(updatedPathParams);

        // 2. Sync Query Parameters
        Map<String, String> updatedQueryParams = new LinkedHashMap<>();
        for (int r = 0; r < queryTableModel.getRowCount(); r++) {
            Object k = queryTableModel.getValueAt(r, 0);
            Object v = queryTableModel.getValueAt(r, 2);
            if (k != null && !k.toString().trim().isEmpty()) {
                updatedQueryParams.put(k.toString().trim(), v != null ? v.toString() : "");
            }
        }
        endpoint.setQueryParams(updatedQueryParams);

        // 3. Sync Body Parameters
        Map<String, String> updatedBodyParams = new LinkedHashMap<>();
        for (int r = 0; r < bodyTableModel.getRowCount(); r++) {
            Object k = bodyTableModel.getValueAt(r, 0);
            Object v = bodyTableModel.getValueAt(r, 2);
            if (k != null && !k.toString().trim().isEmpty()) {
                updatedBodyParams.put(k.toString().trim(), v != null ? v.toString() : "");
            }
        }
        endpoint.setBodyParams(updatedBodyParams);

        // 4. Update requestBodySample if body params exist
        if (!updatedBodyParams.isEmpty()) {
            String updatedBody = buildJsonBody(updatedBodyParams);
            endpoint.setRequestBodySample(updatedBody);
        }

        // 5. Rebuild request and sync customRawRequest
        endpoint.resetCustomRequest();
        HttpRequest newReq = AuthTestEngine_littlespidy.buildDefaultRequest(targetBaseUrl, endpoint);
        if (sessionStore != null && sessionStore.appliesTo(endpoint)) {
            newReq = sessionStore.applyToRequest(newReq, endpoint);
        }

        if (newReq != null && newReq.toByteArray() != null) {
            String rawStr = new String(newReq.toByteArray().getBytes(), StandardCharsets.UTF_8);
            endpoint.setCustomRawRequest(rawStr);
        }

        // 6. Notify callback
        if (onApplyCallback != null) {
            onApplyCallback.accept(newReq);
        }

        if (closeOnSuccess) {
            dispose();
        }
    }

    private String buildJsonBody(Map<String, String> params) {
        StringBuilder sb = new StringBuilder("{\n");
        int count = 0;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (count > 0) sb.append(",\n");
            String key = e.getKey().replace("\"", "\\\"");
            String val = e.getValue() != null ? e.getValue() : "";
            sb.append("  \"").append(key).append("\": ");
            if (isNumericOrBoolean(val)) {
                sb.append(val);
            } else {
                sb.append("\"").append(val.replace("\"", "\\\"")).append("\"");
            }
            count++;
        }
        sb.append("\n}");
        return sb.toString();
    }

    private boolean isNumericOrBoolean(String val) {
        if (val == null || val.isBlank()) return false;
        String trimmed = val.trim();
        if ("true".equalsIgnoreCase(trimmed) || "false".equalsIgnoreCase(trimmed) || "null".equalsIgnoreCase(trimmed)) {
            return true;
        }
        try {
            Double.parseDouble(trimmed);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
