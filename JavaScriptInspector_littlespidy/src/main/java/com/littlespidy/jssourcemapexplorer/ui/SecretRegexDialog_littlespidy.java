// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.engine.SecretAndEndpointMiner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.List;

/**
 * Modal dialog displaying all active secret, token, and credential regex signatures
 * configured in the extension, with real-time search filtering.
 *
 * @author littlespidy
 */
public class SecretRegexDialog_littlespidy extends JDialog {

    private DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> sorter;

    public SecretRegexDialog_littlespidy(Window owner) {
        super(owner, "Secret Detection Signatures and Regex", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setSize(880, 560);
        setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel(new BorderLayout(8, 8));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top Filter Bar
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JLabel searchLbl = new JLabel("Search Signatures:");
        searchLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        searchBar.add(searchLbl);

        JTextField searchField = new JTextField(24);
        searchField.setToolTipText("Filter by category, token name, or regex pattern");
        searchBar.add(searchField);

        JButton resetBtn = new JButton("Reset");
        resetBtn.addActionListener(e -> {
            searchField.setText("");
            if (sorter != null) sorter.setRowFilter(null);
        });
        searchBar.add(resetBtn);

        mainPanel.add(searchBar, BorderLayout.NORTH);

        // Signatures Table
        String[] cols = {"#", "Category", "Token Name", "Regex Pattern"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) {
                return c == 0 ? Integer.class : String.class;
            }
        };

        List<SecretAndEndpointMiner.SecretSignatureInfo> sigs = SecretAndEndpointMiner.getCuratedSignatures();
        int idx = 1;
        for (SecretAndEndpointMiner.SecretSignatureInfo sig : sigs) {
            tableModel.addRow(new Object[]{idx++, sig.category(), sig.name(), sig.pattern()});
        }

        JTable table = new JTable(tableModel);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);
        table.getColumnModel().getColumn(3).setPreferredWidth(440);

        sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void updateFilter() {
                String text = searchField.getText().trim();
                if (text.isEmpty()) {
                    sorter.setRowFilter(null);
                } else {
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
                }
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateFilter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateFilter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateFilter(); }
        });

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(new TitledBorder(String.format("Configured Secret Signatures (%d Active Patterns)", sigs.size())));
        tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);
        mainPanel.add(tablePanel, BorderLayout.CENTER);

        // Bottom Controls
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        btnPanel.add(closeBtn);
        mainPanel.add(btnPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
    }
}
