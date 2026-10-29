// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.model.CorsTechnique_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration sub-panel for CORS testing.
 * Contains target & attacker origin inputs, concurrency & delay settings,
 * a table of 29 PortSwigger techniques with individual row attack buttons,
 * and a batch "Attack All Selected Techniques" execution button.
 */
public class CorsConfigPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private CorsTab_littlespidy corsTab;
    private APIInspectorTab_littlespidy rootTab;

    private final List<CorsTechnique_littlespidy> techniques = new ArrayList<>();
    private final CorsTechniquesTableModel tableModel = new CorsTechniquesTableModel();
    private final JTable techniquesTable = new JTable(tableModel);

    private final JTextField targetUrlField = new JTextField("https://example.com", 20);
    private final JTextField attackerDomainField = new JTextField("evil.com", 12);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 30, 1));
    private final JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 10000, 10));
    private final JTextField runnerNameField = new JTextField("CORS Runner 1", 12);
    private final JButton attackAllBtn = new JButton("Attack All Selected Techniques");

    private int runnerCount = 1;

    public CorsConfigPanel_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.techniques.addAll(CorsTechnique_littlespidy.getDefaultTechniques());

        setBorder(new EmptyBorder(6, 6, 6, 6));
        initComponents();
    }

    public void setCorsTab(CorsTab_littlespidy corsTab) {
        this.corsTab = corsTab;
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.rootTab = rootTab;
    }

    public String getTargetUrl() {
        return targetUrlField.getText().trim();
    }

    public void setTargetUrl(String url) {
        if (url != null && !url.isBlank()) {
            targetUrlField.setText(url.trim());
            tableModel.fireTableDataChanged();
        }
    }

    public String getAttackerDomain() {
        return attackerDomainField.getText().trim();
    }

    public void setAttackerDomain(String domain) {
        if (domain != null && !domain.isBlank()) {
            attackerDomainField.setText(domain.trim());
            tableModel.fireTableDataChanged();
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

    public List<CorsTechnique_littlespidy> getTechniques() {
        return new ArrayList<>(techniques);
    }

    public void setTechniques(List<CorsTechnique_littlespidy> newTechniques) {
        techniques.clear();
        if (newTechniques != null) {
            techniques.addAll(newTechniques);
        } else {
            techniques.addAll(CorsTechnique_littlespidy.getDefaultTechniques());
        }
        tableModel.fireTableDataChanged();
    }

    private void initComponents() {
        // Control Bar
        JPanel controlBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controlBar.setBorder(BorderFactory.createTitledBorder("CORS Testing Parameters"));

        controlBar.add(new JLabel("Target URL:"));
        controlBar.add(targetUrlField);
        targetUrlField.addActionListener(e -> tableModel.fireTableDataChanged());

        controlBar.add(new JLabel("Attacker Domain:"));
        controlBar.add(attackerDomainField);
        attackerDomainField.addActionListener(e -> tableModel.fireTableDataChanged());

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
        String targetUrl = targetUrlField.getText().trim();
        if (targetUrl.isEmpty()) {
            targetUrl = "https://example.com";
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
        if (corsTab == null || rootTab == null) return;

        HttpRequest targetReq = buildTargetRequest();
        String runnerName = runnerNameField.getText().trim();
        if (runnerName.isEmpty()) {
            runnerName = "CORS Runner " + (++runnerCount);
        }

        // Switch to CORS tab
        rootTab.selectTab(corsTab);

        corsTab.executeAttack(
                targetReq,
                getTargetUrl(),
                getAttackerDomain(),
                techniques,
                getThreadCount(),
                getDelayMs(),
                runnerName
        );

        runnerNameField.setText("CORS Runner " + (++runnerCount));
    }

    private void launchSingleTechniqueAttack(int rowIndex) {
        if (corsTab == null || rootTab == null || rowIndex < 0 || rowIndex >= techniques.size()) return;

        CorsTechnique_littlespidy tech = techniques.get(rowIndex);
        HttpRequest targetReq = buildTargetRequest();
        String runnerName = "CORS - " + tech.getName();

        // Switch to CORS tab
        rootTab.selectTab(corsTab);

        corsTab.executeAttack(
                targetReq,
                getTargetUrl(),
                getAttackerDomain(),
                Collections.singletonList(tech),
                1,
                getDelayMs(),
                runnerName
        );
    }

    private class CorsTechniquesTableModel extends AbstractTableModel {
        private final String[] columns = {"Enable", "ID", "Technique Name", "Origin Injected", "Description / Bypass Specifics", "Action"};

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
            CorsTechnique_littlespidy t = techniques.get(rowIndex);
            switch (columnIndex) {
                case 0: return t.isEnabled();
                case 1: return t.getId();
                case 2: return t.getName();
                case 3: return t.resolveOrigin(getTargetUrl(), getAttackerDomain());
                case 4: return t.getDescription() + " (" + t.getBrowserNote() + ")";
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
