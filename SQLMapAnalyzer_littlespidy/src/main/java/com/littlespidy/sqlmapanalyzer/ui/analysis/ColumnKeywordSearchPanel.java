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
 * Tab 2.3: Column Keyword Search.
 * Searches column names across all databases and tables with keyword presets and regex support.
 * Plain ASCII text only.
 */
public class ColumnKeywordSearchPanel extends JPanel {

    private final SqlmapDataStore dataStore;
    private final SQLMapAnalyzerTab mainTab;

    private final JTextField searchField;
    private final JCheckBox regexCheckBox;
    private final JLabel matchCountLabel;
    private final JTable resultsTable;
    private final DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> rowSorter;

    public ColumnKeywordSearchPanel(SqlmapDataStore dataStore, SQLMapAnalyzerTab mainTab) {
        this.dataStore = dataStore;
        this.mainTab = mainTab;

        setLayout(new BorderLayout(0, 8));
        setBorder(new EmptyBorder(8, 10, 10, 10));

        // Top toolbar: Search input, presets, and options
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        searchRow.add(SwingUtils.createBoldLabel("Search Columns:"));

        searchField = new JTextField(22);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { performSearch(); }
            @Override
            public void removeUpdate(DocumentEvent e) { performSearch(); }
            @Override
            public void changedUpdate(DocumentEvent e) { performSearch(); }
        });
        searchRow.add(searchField);

        regexCheckBox = new JCheckBox("Regex");
        regexCheckBox.addActionListener(e -> performSearch());
        searchRow.add(regexCheckBox);

        JButton btnClear = SwingUtils.createStyledButton("Clear");
        btnClear.addActionListener(e -> searchField.setText(""));
        searchRow.add(btnClear);

        matchCountLabel = new JLabel("Matches: 0");
        matchCountLabel.setFont(matchCountLabel.getFont().deriveFont(Font.BOLD, 12));
        searchRow.add(Box.createHorizontalStrut(15));
        searchRow.add(matchCountLabel);

        topContainer.add(searchRow);

        // Presets row
        JPanel presetsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        presetsRow.add(new JLabel("Quick Presets:"));

        String[] presets = {"pass", "user", "email", "token", "secret", "number", "admin", "hash"};
        for (String preset : presets) {
            JButton btn = SwingUtils.createStyledButton(preset);
            btn.addActionListener(e -> {
                regexCheckBox.setSelected(false);
                searchField.setText(preset);
            });
            presetsRow.add(btn);
        }

        topContainer.add(presetsRow);
        add(topContainer, BorderLayout.NORTH);

        // Center: Results Table
        String[] headers = {"Column Name", "Database", "Table Name", "Table Rows", "Target Host"};
        tableModel = new DefaultTableModel(headers, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 3) return Integer.class;
                return String.class;
            }
        };

        resultsTable = new JTable(tableModel);
        resultsTable.setRowHeight(22);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        rowSorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(rowSorter);

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && resultsTable.getSelectedRow() != -1) {
                    navigateToResult();
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(resultsTable);
        add(scrollPane, BorderLayout.CENTER);

        JLabel hint = new JLabel("Hint: Double-click any matching column occurrence to open that table in the Database and Table Viewer tab.");
        hint.setForeground(Color.GRAY);
        add(hint, BorderLayout.SOUTH);
    }

    public void refreshData() {
        performSearch();
    }

    private void performSearch() {
        String query = searchField.getText().trim();
        tableModel.setRowCount(0);

        if (query.isEmpty()) {
            matchCountLabel.setText("Matches: 0");
            return;
        }

        boolean isRegex = regexCheckBox.isSelected();
        List<ColumnOccurrence> results = dataStore.searchColumns(query, isRegex);

        for (ColumnOccurrence occ : results) {
            Vector<Object> row = new Vector<>();
            row.add(occ.getColumnName());
            row.add(occ.getDatabaseName());
            row.add(occ.getTableName());
            row.add(occ.getRowCount());
            row.add(occ.getTargetHost());
            tableModel.addRow(row);
        }

        matchCountLabel.setText("Matches: " + results.size());
    }

    private void navigateToResult() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = resultsTable.convertRowIndexToModel(viewRow);

        String dbName = (String) tableModel.getValueAt(modelRow, 1);
        String tableName = (String) tableModel.getValueAt(modelRow, 2);

        if (mainTab != null) {
            mainTab.navigateToViewer(dbName, tableName);
        }
    }
}
