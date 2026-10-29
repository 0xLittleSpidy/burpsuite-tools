// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.inputvalidation;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Window;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import com.protect7.authanalyzer.inputvalidation.InputValidationConfig_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationPayload_littlespidy;

/**
 * Modal dialog for managing Input Validation payloads, parameter targets, and concurrency settings.
 */
public class InputValidationPayloadsDialog_littlespidy extends JDialog {

    private static final long serialVersionUID = 1L;
    private final InputValidationConfig_littlespidy config;
    private final List<InputValidationPayload_littlespidy> allPayloads;
    private final List<InputValidationPayload_littlespidy> visiblePayloads = new ArrayList<>();
    private final JComboBox<String> categoryComboBox = new JComboBox<>();

    private final JCheckBox chkUrl = new JCheckBox("URL Query", true);
    private final JCheckBox chkBody = new JCheckBox("Body (URL-Encoded)", true);
    private final JCheckBox chkJson = new JCheckBox("JSON Body", true);
    private final JCheckBox chkXml = new JCheckBox("XML Body", true);
    private final JCheckBox chkMultipart = new JCheckBox("Multipart", true);
    private final JCheckBox chkCookie = new JCheckBox("Cookies", false);

    private final JSpinner spinnerThreads = new JSpinner(new SpinnerNumberModel(10, 1, 50, 1));
    private final JSpinner spinnerDelay = new JSpinner(new SpinnerNumberModel(0, 0, 10000, 50));
    private final JSpinner spinnerSizeDiff = new JSpinner(new SpinnerNumberModel(300, 10, 5000, 25));

    private final PayloadsTableModel tableModel;
    private final JTable table;

    public InputValidationPayloadsDialog_littlespidy(Component parent, InputValidationConfig_littlespidy config) {
        super(SwingUtilities.getWindowAncestor(parent), "Input Validation Payloads & Configuration", ModalityType.APPLICATION_MODAL);
        this.config = config;
        this.allPayloads = config.getPayloads();
        this.tableModel = new PayloadsTableModel();
        this.table = new JTable(tableModel);

        setLayout(new BorderLayout(8, 8));
        setSize(920, 600);
        setLocationRelativeTo(parent);

        // Scope & Performance settings panel
        JPanel topSettingsPanel = new JPanel(new GridLayout(2, 1, 4, 4));
        topSettingsPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(8, 10, 4, 10),
                BorderFactory.createTitledBorder("Target Parameter Types & Performance")
        ));

        JPanel scopePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        chkUrl.setSelected(config.isFuzzUrlParams());
        chkBody.setSelected(config.isFuzzBodyParams());
        chkJson.setSelected(config.isFuzzJsonParams());
        chkXml.setSelected(config.isFuzzXmlParams());
        chkMultipart.setSelected(config.isFuzzMultipartParams());
        chkCookie.setSelected(config.isFuzzCookieParams());

        scopePanel.add(new JLabel("Target Scope:"));
        scopePanel.add(chkUrl);
        scopePanel.add(chkBody);
        scopePanel.add(chkJson);
        scopePanel.add(chkXml);
        scopePanel.add(chkMultipart);
        scopePanel.add(chkCookie);
        topSettingsPanel.add(scopePanel);

        JPanel perfPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        spinnerThreads.setValue(config.getMaxConcurrentThreads());
        spinnerDelay.setValue(config.getDelayBetweenRequestsMs());
        spinnerSizeDiff.setValue(config.getSizeDiffPercent());

        perfPanel.add(new JLabel("Threads:"));
        perfPanel.add(spinnerThreads);
        perfPanel.add(new JLabel("Delay (ms):"));
        perfPanel.add(spinnerDelay);
        perfPanel.add(new JLabel("Size Diff Threshold (%):"));
        perfPanel.add(spinnerSizeDiff);
        topSettingsPanel.add(perfPanel);

        // Center: Category Filter, Table, and Actions
        JPanel centerPanel = new JPanel(new BorderLayout(6, 6));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));

        JPanel tableToolbar = new JPanel(new BorderLayout(8, 4));
        JPanel leftFilter = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        leftFilter.add(new JLabel("Category:"));

        populateCategories();
        categoryComboBox.addActionListener(e -> applyCategoryFilter());
        leftFilter.add(categoryComboBox);
        tableToolbar.add(leftFilter, BorderLayout.WEST);

        JPanel rightActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton btnSelectAll = new JButton("Select All");
        btnSelectAll.addActionListener(e -> setPayloadsEnabled(visiblePayloads, true));

        JButton btnDeselectAll = new JButton("Deselect All");
        btnDeselectAll.addActionListener(e -> setPayloadsEnabled(visiblePayloads, false));

        JButton btnResetDefaults = new JButton("Default Essential Set");
        btnResetDefaults.addActionListener(e -> {
            for (InputValidationPayload_littlespidy p : allPayloads) {
                p.setEnabled(p.isDefaultEssential());
            }
            tableModel.fireTableDataChanged();
        });

        JButton btnEnableAllBlns = new JButton("Enable All BLNS (480+)");
        btnEnableAllBlns.addActionListener(e -> {
            setPayloadsEnabled(allPayloads, true);
        });

        JButton btnAddCustom = new JButton("Add Custom");
        btnAddCustom.addActionListener(e -> showAddCustomDialog());

        rightActions.add(btnSelectAll);
        rightActions.add(btnDeselectAll);
        rightActions.add(btnResetDefaults);
        rightActions.add(btnEnableAllBlns);
        rightActions.add(btnAddCustom);
        tableToolbar.add(rightActions, BorderLayout.EAST);

        centerPanel.add(tableToolbar, BorderLayout.NORTH);

        table.setRowHeight(24);
        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(130);
        table.getColumnModel().getColumn(2).setPreferredWidth(170);
        table.getColumnModel().getColumn(3).setPreferredWidth(200);
        table.getColumnModel().getColumn(4).setPreferredWidth(260);

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        table.getColumnModel().getColumn(0).setCellRenderer(table.getDefaultRenderer(Boolean.class));

        centerPanel.add(new JScrollPane(table), BorderLayout.CENTER);

        // Bottom dialog actions
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 8));
        JButton btnCancel = new JButton("Cancel");
        btnCancel.addActionListener(e -> setVisible(false));

        JButton btnSave = new JButton("Save Configuration");
        btnSave.addActionListener(e -> {
            saveConfiguration();
            setVisible(false);
        });

        bottomPanel.add(btnCancel);
        bottomPanel.add(btnSave);

        add(topSettingsPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);

        applyCategoryFilter();
    }

    private void populateCategories() {
        categoryComboBox.removeAllItems();
        categoryComboBox.addItem("All Categories");
        Set<String> categories = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (InputValidationPayload_littlespidy p : allPayloads) {
            if (p.getCategory() != null && !p.getCategory().isEmpty()) {
                categories.add(p.getCategory());
            }
        }
        for (String cat : categories) {
            categoryComboBox.addItem(cat);
        }
    }

    private void applyCategoryFilter() {
        String selected = (String) categoryComboBox.getSelectedItem();
        visiblePayloads.clear();
        if (selected == null || selected.equals("All Categories")) {
            visiblePayloads.addAll(allPayloads);
        } else {
            for (InputValidationPayload_littlespidy p : allPayloads) {
                if (p.getCategory().equalsIgnoreCase(selected)) {
                    visiblePayloads.add(p);
                }
            }
        }
        tableModel.fireTableDataChanged();
    }

    private void setPayloadsEnabled(List<InputValidationPayload_littlespidy> targetList, boolean enabled) {
        for (InputValidationPayload_littlespidy p : targetList) {
            p.setEnabled(enabled);
        }
        tableModel.fireTableDataChanged();
    }

    private void showAddCustomDialog() {
        JTextField nameField = new JTextField(15);
        JTextField valueField = new JTextField(20);
        JTextField catField = new JTextField("Custom", 10);
        JTextField descField = new JTextField(20);

        JPanel panel = new JPanel(new GridLayout(4, 2, 6, 6));
        panel.add(new JLabel("Category:"));
        panel.add(catField);
        panel.add(new JLabel("Payload Name:"));
        panel.add(nameField);
        panel.add(new JLabel("Payload Value:"));
        panel.add(valueField);
        panel.add(new JLabel("Description:"));
        panel.add(descField);

        int res = JOptionPane.showConfirmDialog(this, panel, "Add Custom Fuzz Payload", JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION && !nameField.getText().trim().isEmpty()) {
            String id = "custom_" + System.currentTimeMillis();
            InputValidationPayload_littlespidy custom = new InputValidationPayload_littlespidy(
                    id,
                    catField.getText().trim(),
                    nameField.getText().trim(),
                    valueField.getText(),
                    descField.getText().trim(),
                    true,
                    false
            );
            allPayloads.add(0, custom);
            populateCategories();
            applyCategoryFilter();
        }
    }

    private void saveConfiguration() {
        config.setFuzzUrlParams(chkUrl.isSelected());
        config.setFuzzBodyParams(chkBody.isSelected());
        config.setFuzzJsonParams(chkJson.isSelected());
        config.setFuzzXmlParams(chkXml.isSelected());
        config.setFuzzMultipartParams(chkMultipart.isSelected());
        config.setFuzzCookieParams(chkCookie.isSelected());

        config.setMaxConcurrentThreads((int) spinnerThreads.getValue());
        config.setDelayBetweenRequestsMs((int) spinnerDelay.getValue());
        config.setSizeDiffPercent((int) spinnerSizeDiff.getValue());
        config.setPayloads(allPayloads);
    }

    private class PayloadsTableModel extends AbstractTableModel {
        private final String[] columns = {"Active", "Category", "Payload Name", "Payload Value", "Description"};

        @Override
        public int getRowCount() {
            return visiblePayloads.size();
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
            return columnIndex == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= visiblePayloads.size()) return null;
            InputValidationPayload_littlespidy p = visiblePayloads.get(rowIndex);
            switch (columnIndex) {
                case 0: return p.isEnabled();
                case 1: return p.getCategory();
                case 2: return p.getName();
                case 3: {
                    String v = p.getValue();
                    if (v.isEmpty()) return "\"\" (empty)";
                    return v.length() > 35 ? v.substring(0, 35) + "..." : v;
                }
                case 4: return p.getDescription();
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && rowIndex >= 0 && rowIndex < visiblePayloads.size()) {
                visiblePayloads.get(rowIndex).setEnabled((Boolean) aValue);
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
