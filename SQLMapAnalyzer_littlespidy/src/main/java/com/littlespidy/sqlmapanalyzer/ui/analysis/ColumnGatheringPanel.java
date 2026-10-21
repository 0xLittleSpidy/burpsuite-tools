// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.analysis;

import com.littlespidy.sqlmapanalyzer.model.ColumnOccurrence;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
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
 * Tab 2.2: Column Gathering.
 * Displays unique column names grouped together, showing all occurrences across databases and tables.
 * Plain ASCII text only.
 */
public class ColumnGatheringPanel extends JPanel {

    private final SqlmapDataStore dataStore;
    private final SQLMapAnalyzerTab mainTab;

    private final JTextField filterColumnsField;
    private final JTable columnsTable;
    private final DefaultTableModel columnsTableModel;
    private TableRowSorter<DefaultTableModel> columnRowSorter;

    private final JLabel occurrencesHeaderLabel;
    private final JTable occurrencesTable;
    private final DefaultTableModel occurrencesTableModel;
    private TableRowSorter<DefaultTableModel> occurrenceRowSorter;

    public ColumnGatheringPanel(SqlmapDataStore dataStore, SQLMapAnalyzerTab mainTab) {
        this.dataStore = dataStore;
        this.mainTab = mainTab;

        setLayout(new BorderLayout(0, 8));
        setBorder(new EmptyBorder(8, 10, 10, 10));

        // Master-Detail Split Pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.35);

        // Left Panel: Unique Columns Master View
        JPanel leftPanel = new JPanel(new BorderLayout(0, 6));
        leftPanel.setBorder(new EmptyBorder(0, 0, 0, 5));

        JPanel leftTopBar = new JPanel(new BorderLayout(5, 0));
        leftTopBar.add(SwingUtils.createBoldLabel("Unique Columns:"), BorderLayout.WEST);

        filterColumnsField = new JTextField();
        filterColumnsField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyColumnFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyColumnFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyColumnFilter(); }
        });
        leftTopBar.add(filterColumnsField, BorderLayout.CENTER);

        JButton btnClear = SwingUtils.createStyledButton("Clear");
        btnClear.addActionListener(e -> filterColumnsField.setText(""));
        leftTopBar.add(btnClear, BorderLayout.EAST);

        leftPanel.add(leftTopBar, BorderLayout.NORTH);

        String[] colHeaderCols = {"Column Name", "Tables"};
        columnsTableModel = new DefaultTableModel(colHeaderCols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 1) return Integer.class;
                return String.class;
            }
        };

        columnsTable = new JTable(columnsTableModel);
        columnsTable.setRowHeight(22);
        columnsTable.setFillsViewportHeight(true);
        columnsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        columnRowSorter = new TableRowSorter<>(columnsTableModel);
        columnsTable.setRowSorter(columnRowSorter);

        columnsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onColumnSelected();
            }
        });

        JScrollPane leftScroll = new JScrollPane(columnsTable);
        leftPanel.add(leftScroll, BorderLayout.CENTER);

        splitPane.setLeftComponent(leftPanel);

        // Right Panel: Occurrences Detail View
        JPanel rightPanel = new JPanel(new BorderLayout(0, 6));
        rightPanel.setBorder(new EmptyBorder(0, 5, 0, 0));

        occurrencesHeaderLabel = new JLabel("Select a column to inspect its occurrences across databases.");
        occurrencesHeaderLabel.setFont(occurrencesHeaderLabel.getFont().deriveFont(Font.BOLD, 12));
        rightPanel.add(occurrencesHeaderLabel, BorderLayout.NORTH);

        String[] occurrenceHeaders = {"Database", "Table Name", "Table Rows", "Target Host"};
        occurrencesTableModel = new DefaultTableModel(occurrenceHeaders, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 2) return Integer.class;
                return String.class;
            }
        };

        occurrencesTable = new JTable(occurrencesTableModel);
        occurrencesTable.setRowHeight(22);
        occurrencesTable.setFillsViewportHeight(true);
        occurrencesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        occurrenceRowSorter = new TableRowSorter<>(occurrencesTableModel);
        occurrencesTable.setRowSorter(occurrenceRowSorter);

        occurrencesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && occurrencesTable.getSelectedRow() != -1) {
                    navigateToOccurrence();
                }
            }
        });

        JScrollPane rightScroll = new JScrollPane(occurrencesTable);
        rightPanel.add(rightScroll, BorderLayout.CENTER);

        JLabel rightHint = new JLabel("Hint: Double-click an occurrence row to jump to the table data in the Viewer tab.");
        rightHint.setForeground(Color.GRAY);
        rightPanel.add(rightHint, BorderLayout.SOUTH);

        splitPane.setRightComponent(rightPanel);

        add(splitPane, BorderLayout.CENTER);
    }

    public void refreshData() {
        columnsTableModel.setRowCount(0);
        occurrencesTableModel.setRowCount(0);
        occurrencesHeaderLabel.setText("Select a column to inspect its occurrences across databases.");

        List<String> uniqueCols = dataStore.getUniqueColumnNames();
        for (String colName : uniqueCols) {
            List<ColumnOccurrence> occs = dataStore.getColumnOccurrences(colName);
            Vector<Object> row = new Vector<>();
            row.add(colName);
            row.add(occs.size());
            columnsTableModel.addRow(row);
        }

        applyColumnFilter();

        if (columnsTable.getRowCount() > 0) {
            columnsTable.setRowSelectionInterval(0, 0);
        }
    }

    private void onColumnSelected() {
        int viewRow = columnsTable.getSelectedRow();
        if (viewRow < 0) {
            occurrencesTableModel.setRowCount(0);
            occurrencesHeaderLabel.setText("No column selected.");
            return;
        }

        int modelRow = columnsTable.convertRowIndexToModel(viewRow);
        String colName = (String) columnsTableModel.getValueAt(modelRow, 0);

        List<ColumnOccurrence> occs = dataStore.getColumnOccurrences(colName);
        occurrencesTableModel.setRowCount(0);

        for (ColumnOccurrence occ : occs) {
            Vector<Object> row = new Vector<>();
            row.add(occ.getDatabaseName());
            row.add(occ.getTableName());
            row.add(occ.getRowCount());
            row.add(occ.getTargetHost());
            occurrencesTableModel.addRow(row);
        }

        occurrencesHeaderLabel.setText("Column: '" + colName + "' found in " + occs.size() + " table(s):");
    }

    private void applyColumnFilter() {
        if (columnRowSorter == null) return;
        String query = filterColumnsField.getText().trim();
        if (query.isEmpty()) {
            columnRowSorter.setRowFilter(null);
        } else {
            try {
                columnRowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + query));
            } catch (Exception e) {
                columnRowSorter.setRowFilter(null);
            }
        }
    }

    private void navigateToOccurrence() {
        int viewRow = occurrencesTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = occurrencesTable.convertRowIndexToModel(viewRow);

        String dbName = (String) occurrencesTableModel.getValueAt(modelRow, 0);
        String tableName = (String) occurrencesTableModel.getValueAt(modelRow, 1);

        if (mainTab != null) {
            mainTab.navigateToViewer(dbName, tableName);
        }
    }
}
