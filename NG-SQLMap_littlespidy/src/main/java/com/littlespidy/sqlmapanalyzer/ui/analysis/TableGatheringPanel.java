// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.analysis;

import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;
import com.littlespidy.sqlmapanalyzer.ui.SQLMapAnalyzerTab;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Vector;

/**
 * Tab 2.1: Table Gathering.
 * Displays all tables discovered across all databases with column and row statistics.
 * Plain ASCII text only.
 */
public class TableGatheringPanel extends JPanel {

    private final SqlmapDataStore dataStore;
    private final SQLMapAnalyzerTab mainTab;

    private final JTextField filterField;
    private final JTable tablesTable;
    private final DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> rowSorter;
    private final JLabel countLabel;

    public TableGatheringPanel(SqlmapDataStore dataStore, SQLMapAnalyzerTab mainTab) {
        this.dataStore = dataStore;
        this.mainTab = mainTab;

        setLayout(new BorderLayout(0, 8));
        setBorder(new EmptyBorder(8, 10, 10, 10));

        // Top toolbar: Filter box and summary
        JPanel topBar = new JPanel(new BorderLayout(10, 0));

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        filterPanel.add(SwingUtils.createBoldLabel("Filter Tables:"));
        filterField = new JTextField(20);
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        filterPanel.add(filterField);

        JButton btnClear = SwingUtils.createStyledButton("Clear");
        btnClear.addActionListener(e -> filterField.setText(""));
        filterPanel.add(btnClear);

        topBar.add(filterPanel, BorderLayout.WEST);

        countLabel = new JLabel("Total Tables: 0");
        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD, 12));
        topBar.add(countLabel, BorderLayout.EAST);

        add(topBar, BorderLayout.NORTH);

        // Center: JTable
        String[] columnHeaders = {"Database", "Table Name", "Columns", "Rows", "File Size", "Target Host"};
        tableModel = new DefaultTableModel(columnHeaders, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 2 || columnIndex == 3) return Integer.class;
                return String.class;
            }
        };

        tablesTable = new JTable(tableModel);
        tablesTable.setRowHeight(22);
        tablesTable.setFillsViewportHeight(true);
        tablesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        rowSorter = new TableRowSorter<>(tableModel);
        tablesTable.setRowSorter(rowSorter);

        // Double-click navigation
        tablesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && tablesTable.getSelectedRow() != -1) {
                    navigateToSelectedTable();
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(tablesTable);
        add(scrollPane, BorderLayout.CENTER);

        // Hint label at bottom
        JLabel hintLabel = new JLabel("Hint: Double-click any table row to view its data in the Database and Table Viewer tab.");
        hintLabel.setForeground(Color.GRAY);
        add(hintLabel, BorderLayout.SOUTH);
    }

    public void refreshData() {
        tableModel.setRowCount(0);
        List<TableMetadata> allTables = dataStore.getAllTables();

        for (TableMetadata meta : allTables) {
            Vector<Object> row = new Vector<>();
            row.add(meta.getDatabaseName());
            row.add(meta.getTableName());
            row.add(meta.getColumnCount());
            row.add(meta.getRowCount());
            row.add(formatFileSize(meta.getFileSizeBytes()));
            row.add(meta.getTargetHost());
            tableModel.addRow(row);
        }

        countLabel.setText("Total Tables: " + allTables.size());
        applyFilter();
    }

    private void applyFilter() {
        if (rowSorter == null) return;
        String query = filterField.getText().trim();
        if (query.isEmpty()) {
            rowSorter.setRowFilter(null);
        } else {
            try {
                rowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + query));
            } catch (Exception e) {
                rowSorter.setRowFilter(null);
            }
        }
    }

    private void navigateToSelectedTable() {
        int viewRow = tablesTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = tablesTable.convertRowIndexToModel(viewRow);

        String dbName = (String) tableModel.getValueAt(modelRow, 0);
        String tableName = (String) tableModel.getValueAt(modelRow, 1);

        if (mainTab != null) {
            mainTab.navigateToViewer(dbName, tableName);
        }
    }

    private String formatFileSize(long bytes) {
        if (bytes <= 0) return "0 B";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
    }
}
