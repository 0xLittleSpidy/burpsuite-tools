// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.model.InputValidationTechnique_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration sub-panel for Input Validation fuzzing.
 * Contains target endpoint input, concurrency & delay settings,
 * a table of vulnerability categories with individual row attack buttons,
 * and a batch "Attack All Selected Categories" execution button.
 */
public class InputValidationConfigPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private InputValidationTab_littlespidy inputValidationTab;
    private APIInspectorTab_littlespidy rootTab;

    private final List<InputValidationTechnique_littlespidy> techniques = new ArrayList<>();
    private final FuzzTechniquesTableModel tableModel = new FuzzTechniquesTableModel();
    private final JTable techniquesTable = new JTable(tableModel);

    private final JTextField targetEndpointField = new JTextField("https://example.com/api/v1/search?query=test", 24);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 30, 1));
    private final JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 10000, 10));
    private final JTextField runnerNameField = new JTextField("Input Validation Runner 1", 14);
    private final JButton attackAllBtn = new JButton("Attack All Selected Categories");

    private int runnerCount = 1;

    public InputValidationConfigPanel_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.techniques.addAll(InputValidationTechnique_littlespidy.getDefaultTechniques());

        setBorder(new EmptyBorder(6, 6, 6, 6));
        initComponents();
    }

    public void setInputValidationTab(InputValidationTab_littlespidy inputValidationTab) {
        this.inputValidationTab = inputValidationTab;
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.rootTab = rootTab;
    }

    public String getTargetEndpoint() {
        return targetEndpointField.getText().trim();
    }

    public void setTargetEndpoint(String url) {
        if (url != null && !url.isBlank()) {
            targetEndpointField.setText(url.trim());
        }
    }

    public int getThreadCount() {
        return (Integer) threadSpinner.getValue();
    }

    public void setThreadCount(int count) {
        threadSpinner.setValue(Math.max(1, count));
    }

    public int getDelayMs() {
        return (Integer) delaySpinner.getValue();
    }

    public void setDelayMs(int delay) {
        delaySpinner.setValue(Math.max(0, delay));
    }

    public List<InputValidationTechnique_littlespidy> getTechniques() {
        return new ArrayList<>(techniques);
    }

    public void setTechniques(List<InputValidationTechnique_littlespidy> newTechniques) {
        techniques.clear();
        if (newTechniques != null) {
            techniques.addAll(newTechniques);
        } else {
            techniques.addAll(InputValidationTechnique_littlespidy.getDefaultTechniques());
        }
        tableModel.fireTableDataChanged();
    }

    private void initComponents() {
        // Control Bar
        JPanel controlBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controlBar.setBorder(BorderFactory.createTitledBorder("Input Validation Parameters"));

        controlBar.add(new JLabel("Target Endpoint:"));
        controlBar.add(targetEndpointField);

        controlBar.add(new JLabel("Threads:"));
        controlBar.add(threadSpinner);

        controlBar.add(new JLabel("Delay (ms):"));
        controlBar.add(delaySpinner);

        controlBar.add(new JLabel("Runner Name:"));
        controlBar.add(runnerNameField);

        attackAllBtn.setFont(attackAllBtn.getFont().deriveFont(Font.BOLD));
        attackAllBtn.addActionListener(e -> launchBatchAttack());
        controlBar.add(attackAllBtn);

        add(controlBar, BorderLayout.NORTH);

        // Techniques Table
        techniquesTable.setFillsViewportHeight(true);
        techniquesTable.setRowHeight(24);
        techniquesTable.getColumnModel().getColumn(0).setMaxWidth(60);
        techniquesTable.getColumnModel().getColumn(1).setMaxWidth(70);
        techniquesTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        techniquesTable.getColumnModel().getColumn(3).setPreferredWidth(260);
        techniquesTable.getColumnModel().getColumn(4).setPreferredWidth(300);
        techniquesTable.getColumnModel().getColumn(5).setMaxWidth(100);

        // Setup Button Column Renderer & Editor
        techniquesTable.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());
        techniquesTable.getColumnModel().getColumn(5).setCellEditor(new ButtonEditor(new JCheckBox(), this::launchSingleTechniqueAttack));

        add(new JScrollPane(techniquesTable), BorderLayout.CENTER);
    }

    private HttpRequest buildTargetRequest() {
        String targetUrl = targetEndpointField.getText().trim();
        if (targetUrl.isEmpty()) {
            targetUrl = "https://example.com/api/v1/search?query=test";
        }
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
        }

        HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl);
        if (request == null) {
            HttpService service = HttpService.httpService("localhost", 443, true);
            request = HttpRequest.httpRequest(service, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        }
        return request;
    }

    private void launchBatchAttack() {
        if (inputValidationTab == null || rootTab == null) return;

        HttpRequest targetReq = buildTargetRequest();
        String runnerName = runnerNameField.getText().trim();
        if (runnerName.isEmpty()) {
            runnerName = "Input Validation Runner " + (++runnerCount);
        }

        // Switch to Input Validation tab
        rootTab.selectTab(inputValidationTab);

        inputValidationTab.executeAttack(
                targetReq,
                techniques,
                getThreadCount(),
                getDelayMs(),
                runnerName
        );

        runnerNameField.setText("Input Validation Runner " + (++runnerCount));
    }

    private void launchSingleTechniqueAttack(int rowIndex) {
        if (inputValidationTab == null || rootTab == null || rowIndex < 0 || rowIndex >= techniques.size()) return;

        InputValidationTechnique_littlespidy tech = techniques.get(rowIndex);
        HttpRequest targetReq = buildTargetRequest();
        String runnerName = "Fuzz - " + tech.getCategory();

        // Switch to Input Validation tab
        rootTab.selectTab(inputValidationTab);

        inputValidationTab.executeAttack(
                targetReq,
                Collections.singletonList(tech),
                1,
                getDelayMs(),
                runnerName
        );
    }

    private class FuzzTechniquesTableModel extends AbstractTableModel {
        private final String[] columns = {"Enable", "ID", "Vulnerability Category", "Payload Samples", "Description / Match Signatures", "Action"};

        @Override
        public int getRowCount() {
            return techniques.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Boolean.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0 || columnIndex == 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= techniques.size()) return "";
            InputValidationTechnique_littlespidy t = techniques.get(rowIndex);
            switch (columnIndex) {
                case 0: return t.isEnabled();
                case 1: return t.getId();
                case 2: return t.getCategory();
                case 3: return String.join(", ", t.getSamplePayloads());
                case 4: return t.getDescription();
                case 5: return "Attack";
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (rowIndex >= 0 && rowIndex < techniques.size() && columnIndex == 0) {
                techniques.get(rowIndex).setEnabled((Boolean) aValue);
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }

    private static class ButtonRenderer extends JButton implements TableCellRenderer {
        public ButtonRenderer() {
            setOpaque(true);
            setText("Attack");
        }
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            setText(value != null ? value.toString() : "Attack");
            return this;
        }
    }

    private static class ButtonEditor extends DefaultCellEditor {
        private final JButton button = new JButton();
        private final java.util.function.Consumer<Integer> onAction;
        private int currentRow = -1;

        public ButtonEditor(JCheckBox checkBox, java.util.function.Consumer<Integer> onAction) {
            super(checkBox);
            this.onAction = onAction;
            button.setOpaque(true);
            button.addActionListener(e -> {
                fireEditingStopped();
                if (onAction != null && currentRow != -1) {
                    onAction.accept(currentRow);
                }
            });
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            currentRow = row;
            button.setText(value != null ? value.toString() : "Attack");
            return button;
        }

        @Override
        public Object getCellEditorValue() {
            return "Attack";
        }
    }
}
