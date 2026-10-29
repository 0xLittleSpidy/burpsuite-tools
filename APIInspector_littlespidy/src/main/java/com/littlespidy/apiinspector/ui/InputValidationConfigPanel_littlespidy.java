// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.model.InputValidationTechnique_littlespidy;
import com.littlespidy.apiinspector.model.NaughtyStringsParser_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration sub-panel for Input Validation fuzzing.
 * Contains target endpoint input, concurrency & delay settings,
 * category filtering (Standard, BLNS, Custom), a custom wordlist loader button,
 * a table of vulnerability categories with individual row attack buttons,
 * and a batch "Attack All Selected Categories" execution button.
 */
public class InputValidationConfigPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private InputValidationTab_littlespidy inputValidationTab;
    private APIInspectorTab_littlespidy rootTab;

    private final List<InputValidationTechnique_littlespidy> allTechniques = new ArrayList<>();
    private final List<InputValidationTechnique_littlespidy> displayedTechniques = new ArrayList<>();
    private final FuzzTechniquesTableModel tableModel = new FuzzTechniquesTableModel();
    private final JTable techniquesTable = new JTable(tableModel);

    private final JTextField targetEndpointField = new JTextField("https://example.com/api/v1/search?query=test", 24);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 30, 1));
    private final JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 10000, 10));
    private final JTextField runnerNameField = new JTextField("Input Validation Runner 1", 14);
    private final JButton attackAllBtn = new JButton("Attack All Selected Categories");

    private final JComboBox<String> filterCombo = new JComboBox<>(new String[]{
            "All Categories", "Standard OWASP", "Naughty Strings (BLNS)", "Custom Wordlists"
    });

    private int runnerCount = 1;

    public InputValidationConfigPanel_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.allTechniques.addAll(InputValidationTechnique_littlespidy.getDefaultTechniques());
        this.displayedTechniques.addAll(this.allTechniques);

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
        return new ArrayList<>(allTechniques);
    }

    public void setTechniques(List<InputValidationTechnique_littlespidy> newTechniques) {
        allTechniques.clear();
        if (newTechniques != null) {
            allTechniques.addAll(newTechniques);
        } else {
            allTechniques.addAll(InputValidationTechnique_littlespidy.getDefaultTechniques());
        }
        applyFilter();
    }

    private void applyFilter() {
        String selected = (String) filterCombo.getSelectedItem();
        displayedTechniques.clear();

        if ("Standard OWASP".equals(selected)) {
            for (InputValidationTechnique_littlespidy t : allTechniques) {
                if (!t.isBlns() && !t.getId().startsWith("custom_")) {
                    displayedTechniques.add(t);
                }
            }
        } else if ("Naughty Strings (BLNS)".equals(selected)) {
            for (InputValidationTechnique_littlespidy t : allTechniques) {
                if (t.isBlns()) {
                    displayedTechniques.add(t);
                }
            }
        } else if ("Custom Wordlists".equals(selected)) {
            for (InputValidationTechnique_littlespidy t : allTechniques) {
                if (t.getId().startsWith("custom_")) {
                    displayedTechniques.add(t);
                }
            }
        } else {
            displayedTechniques.addAll(allTechniques);
        }

        tableModel.fireTableDataChanged();
    }

    private void initComponents() {
        // Control Container with two rows
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        // Row 1: Target parameters and Execution
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row1.setBorder(BorderFactory.createTitledBorder("Input Validation Parameters"));

        row1.add(new JLabel("Target Endpoint:"));
        row1.add(targetEndpointField);

        row1.add(new JLabel("Threads:"));
        row1.add(threadSpinner);

        row1.add(new JLabel("Delay (ms):"));
        row1.add(delaySpinner);

        row1.add(new JLabel("Runner Name:"));
        row1.add(runnerNameField);

        attackAllBtn.setFont(attackAllBtn.getFont().deriveFont(Font.BOLD));
        attackAllBtn.addActionListener(e -> launchBatchAttack());
        row1.add(attackAllBtn);
        topContainer.add(row1);

        // Row 2: Category Filter and Wordlist Management
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row2.add(new JLabel("Category Filter:"));
        filterCombo.addActionListener(e -> applyFilter());
        row2.add(filterCombo);

        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> {
            for (InputValidationTechnique_littlespidy t : displayedTechniques) {
                t.setEnabled(true);
            }
            tableModel.fireTableDataChanged();
        });
        row2.add(selectAllBtn);

        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> {
            for (InputValidationTechnique_littlespidy t : displayedTechniques) {
                t.setEnabled(false);
            }
            tableModel.fireTableDataChanged();
        });
        row2.add(deselectAllBtn);

        JButton loadCustomBtn = new JButton("Load Custom Wordlist...");
        loadCustomBtn.addActionListener(e -> loadCustomWordlist());
        row2.add(loadCustomBtn);

        topContainer.add(row2);
        add(topContainer, BorderLayout.NORTH);

        // Techniques Table
        techniquesTable.setFillsViewportHeight(true);
        techniquesTable.setRowHeight(24);
        techniquesTable.getColumnModel().getColumn(0).setMaxWidth(60);
        techniquesTable.getColumnModel().getColumn(1).setMaxWidth(130);
        techniquesTable.getColumnModel().getColumn(2).setPreferredWidth(210);
        techniquesTable.getColumnModel().getColumn(3).setMaxWidth(80);
        techniquesTable.getColumnModel().getColumn(4).setPreferredWidth(250);
        techniquesTable.getColumnModel().getColumn(5).setPreferredWidth(250);
        techniquesTable.getColumnModel().getColumn(6).setMaxWidth(100);

        // Setup Button Column Renderer & Editor
        techniquesTable.getColumnModel().getColumn(6).setCellRenderer(new ButtonRenderer());
        techniquesTable.getColumnModel().getColumn(6).setCellEditor(new ButtonEditor(new JCheckBox(), this::launchSingleTechniqueAttack));

        add(new JScrollPane(techniquesTable), BorderLayout.CENTER);
    }

    private void loadCustomWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Wordlist File (.txt)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try {
                InputValidationTechnique_littlespidy customTech = NaughtyStringsParser_littlespidy.parseCustomFile(f);
                allTechniques.add(customTech);
                applyFilter();
                JOptionPane.showMessageDialog(this,
                        "Successfully loaded wordlist: " + f.getName() + " (" + customTech.getPayloadCount() + " payloads).",
                        "Wordlist Loaded",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to load wordlist: " + ex.getMessage(),
                        "Load Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
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
                allTechniques,
                getThreadCount(),
                getDelayMs(),
                runnerName
        );

        runnerNameField.setText("Input Validation Runner " + (++runnerCount));
    }

    private void launchSingleTechniqueAttack(int rowIndex) {
        if (inputValidationTab == null || rootTab == null || rowIndex < 0 || rowIndex >= displayedTechniques.size()) return;

        InputValidationTechnique_littlespidy tech = displayedTechniques.get(rowIndex);
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
        private final String[] columns = {"Enable", "ID", "Vulnerability Category", "Count", "Payload Samples", "Description / Match Signatures", "Action"};

        @Override
        public int getRowCount() {
            return displayedTechniques.size();
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
            if (columnIndex == 3) return Integer.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0 || columnIndex == 6;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= displayedTechniques.size()) return "";
            InputValidationTechnique_littlespidy t = displayedTechniques.get(rowIndex);
            switch (columnIndex) {
                case 0: return t.isEnabled();
                case 1: return t.getId();
                case 2: return t.getCategory();
                case 3: return t.getPayloadCount();
                case 4: return getSamplePreview(t);
                case 5: return t.getDescription();
                case 6: return "Attack";
                default: return "";
            }
        }

        private String getSamplePreview(InputValidationTechnique_littlespidy t) {
            List<String> samples = t.getSamplePayloads();
            if (samples.isEmpty()) return "";
            if (samples.size() <= 3) {
                return String.join(", ", samples);
            }
            return samples.get(0) + ", " + samples.get(1) + ", " + samples.get(2) + " (+" + (samples.size() - 3) + " more)";
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (rowIndex >= 0 && rowIndex < displayedTechniques.size() && columnIndex == 0) {
                displayedTechniques.get(rowIndex).setEnabled((Boolean) aValue);
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
