// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.viewer;

import com.littlespidy.sqlmapanalyzer.model.DatabaseModel;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.model.TableData;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;
import com.littlespidy.sqlmapanalyzer.parser.SqlmapCsvParser;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * Tab 1: Database and Table Viewer.
 * Displays tables, columns, rows, search filter, and column visibility selector.
 * Plain ASCII text only.
 */
public class TableViewerPanel extends JPanel {

    private final SqlmapDataStore dataStore;
    private final SqlmapCsvParser csvParser;

    private final JComboBox<String> dbComboBox;
    private final JComboBox<String> tableComboBox;
    private final JButton btnColumnVisibility;
    private final JTextField searchField;
    private final JButton btnClearSearch;
    private final JButton btnExportCsv;

    private final JLabel breadcrumbLabel;
    private final JTable dataTable;
    private final DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> rowSorter;

    private TableMetadata currentTableMetadata = null;
    private TableData currentFullData = null;
    private List<String> visibleColumns = new ArrayList<>();
    private boolean isUpdatingDropdowns = false;

    public TableViewerPanel(SqlmapDataStore dataStore) {
        this.dataStore = dataStore;
        this.csvParser = new SqlmapCsvParser();

        setLayout(new BorderLayout(0, 8));
        setBorder(new EmptyBorder(8, 10, 10, 10));

        // Top control toolbar
        JPanel topToolbar = new JPanel(new BorderLayout(10, 5));

        JPanel selectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        selectionPanel.add(SwingUtils.createBoldLabel("Database:"));
        dbComboBox = new JComboBox<>();
        dbComboBox.setPreferredSize(new Dimension(200, 26));
        dbComboBox.addActionListener(e -> {
            if (!isUpdatingDropdowns) {
                onDatabaseChanged();
            }
        });
        selectionPanel.add(dbComboBox);

        selectionPanel.add(SwingUtils.createBoldLabel("Table:"));
        tableComboBox = new JComboBox<>();
        tableComboBox.setPreferredSize(new Dimension(220, 26));
        tableComboBox.addActionListener(e -> {
            if (!isUpdatingDropdowns) {
                onTableChanged();
            }
        });
        selectionPanel.add(tableComboBox);

        btnColumnVisibility = SwingUtils.createStyledButton("Visible Columns...");
        btnColumnVisibility.setEnabled(false);
        btnColumnVisibility.addActionListener(e -> openColumnVisibilityDialog());
        selectionPanel.add(btnColumnVisibility);

        btnExportCsv = SwingUtils.createStyledButton("Export CSV...");
        btnExportCsv.setEnabled(false);
        btnExportCsv.addActionListener(e -> onExportCsv());
        selectionPanel.add(btnExportCsv);

        topToolbar.add(selectionPanel, BorderLayout.WEST);

        // Search panel on right
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        searchPanel.add(new JLabel("Search Table:"));
        searchField = new JTextField(15);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applySearchFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applySearchFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applySearchFilter(); }
        });
        searchPanel.add(searchField);

        btnClearSearch = SwingUtils.createStyledButton("Clear");
        btnClearSearch.addActionListener(e -> searchField.setText(""));
        searchPanel.add(btnClearSearch);

        topToolbar.add(searchPanel, BorderLayout.EAST);

        add(topToolbar, BorderLayout.NORTH);

        // Center Panel: Breadcrumb header + JTable
        JPanel centerPanel = new JPanel(new BorderLayout(0, 4));

        breadcrumbLabel = new JLabel("Database: [None] | Table: [None] | 0 Columns | 0 Rows");
        breadcrumbLabel.setFont(breadcrumbLabel.getFont().deriveFont(Font.BOLD, 12));
        breadcrumbLabel.setBorder(new EmptyBorder(2, 4, 4, 4));
        centerPanel.add(breadcrumbLabel, BorderLayout.NORTH);

        tableModel = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        dataTable = new JTable(tableModel);
        dataTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        dataTable.setFillsViewportHeight(true);
        dataTable.setRowHeight(22);
        dataTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        rowSorter = new TableRowSorter<>(tableModel);
        dataTable.setRowSorter(rowSorter);

        JScrollPane scrollPane = new JScrollPane(dataTable);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);
    }

    public void refreshDatabases() {
        isUpdatingDropdowns = true;
        try {
            dbComboBox.removeAllItems();
            List<DatabaseModel> dbs = dataStore.getAllDatabases();
            for (DatabaseModel db : dbs) {
                dbComboBox.addItem(db.getDisplayName());
            }

            if (dbComboBox.getItemCount() > 0) {
                dbComboBox.setSelectedIndex(0);
                populateTablesForSelectedDatabase();
            } else {
                tableComboBox.removeAllItems();
                clearTableView();
            }
        } finally {
            isUpdatingDropdowns = false;
        }

        if (tableComboBox.getItemCount() > 0) {
            tableComboBox.setSelectedIndex(0);
            loadCurrentSelectedTable();
        }
    }

    private void onDatabaseChanged() {
        populateTablesForSelectedDatabase();
        if (tableComboBox.getItemCount() > 0) {
            tableComboBox.setSelectedIndex(0);
            loadCurrentSelectedTable();
        } else {
            clearTableView();
        }
    }

    private void populateTablesForSelectedDatabase() {
        tableComboBox.removeAllItems();
        DatabaseModel selectedDb = getSelectedDatabaseModel();
        if (selectedDb != null) {
            for (String tableName : selectedDb.getTableNames()) {
                tableComboBox.addItem(tableName);
            }
        }
    }

    private void onTableChanged() {
        loadCurrentSelectedTable();
    }

    public void selectDatabaseAndTable(String dbName, String tableName) {
        if (dbName == null || tableName == null) return;

        isUpdatingDropdowns = true;
        try {
            for (int i = 0; i < dbComboBox.getItemCount(); i++) {
                String item = dbComboBox.getItemAt(i);
                if (item.equalsIgnoreCase(dbName) || item.endsWith(" / " + dbName) || item.toLowerCase().contains(dbName.toLowerCase())) {
                    dbComboBox.setSelectedIndex(i);
                    break;
                }
            }
            populateTablesForSelectedDatabase();
            for (int i = 0; i < tableComboBox.getItemCount(); i++) {
                String item = tableComboBox.getItemAt(i);
                if (item.equalsIgnoreCase(tableName)) {
                    tableComboBox.setSelectedIndex(i);
                    break;
                }
            }
        } finally {
            isUpdatingDropdowns = false;
        }

        loadCurrentSelectedTable();
    }

    private void loadCurrentSelectedTable() {
        DatabaseModel db = getSelectedDatabaseModel();
        String tableName = (String) tableComboBox.getSelectedItem();

        if (db == null || tableName == null) {
            clearTableView();
            return;
        }

        TableMetadata meta = db.getTable(tableName);
        if (meta == null) {
            clearTableView();
            return;
        }

        this.currentTableMetadata = meta;
        String cacheKey = meta.getQualifiedName();

        TableData cachedData = dataStore.getCachedTableData(cacheKey);
        if (cachedData != null) {
            this.currentFullData = cachedData;
            displayTableData();
            return;
        }

        // Load asynchronously to prevent UI freeze
        breadcrumbLabel.setText("Loading table data: " + meta.getQualifiedName() + "...");
        btnColumnVisibility.setEnabled(false);
        btnExportCsv.setEnabled(false);

        SwingWorker<TableData, Void> worker = new SwingWorker<>() {
            @Override
            protected TableData doInBackground() throws Exception {
                File csvFile = meta.getCsvFile();
                if (csvFile != null && csvFile.exists()) {
                    return csvParser.parseFullTable(csvFile);
                }
                return new TableData(meta.getColumnNames(), new ArrayList<>());
            }

            @Override
            protected void done() {
                try {
                    TableData data = get();
                    currentFullData = data;
                    dataStore.putTableData(cacheKey, data);
                    displayTableData();
                } catch (Exception e) {
                    breadcrumbLabel.setText("Error loading table: " + e.getMessage());
                }
            }
        };

        worker.execute();
    }

    private void displayTableData() {
        if (currentTableMetadata == null || currentFullData == null) {
            clearTableView();
            return;
        }

        visibleColumns = new ArrayList<>(currentFullData.getHeaders());
        updateTableGrid();

        btnColumnVisibility.setEnabled(true);
        btnExportCsv.setEnabled(true);
    }

    private void updateTableGrid() {
        if (currentFullData == null) return;

        List<String> allHeaders = currentFullData.getHeaders();
        List<Integer> visibleIndices = new ArrayList<>();
        Vector<String> colIdentifiers = new Vector<>();

        for (int i = 0; i < allHeaders.size(); i++) {
            String h = allHeaders.get(i);
            if (visibleColumns.contains(h)) {
                visibleIndices.add(i);
                colIdentifiers.add(h);
            }
        }

        Vector<Vector<Object>> rowVectors = new Vector<>();
        for (List<String> row : currentFullData.getRows()) {
            Vector<Object> rowVec = new Vector<>(visibleIndices.size());
            for (int idx : visibleIndices) {
                if (idx < row.size()) {
                    String val = row.get(idx);
                    rowVec.add(val != null && !val.isBlank() ? val : "[NULL]");
                } else {
                    rowVec.add("[NULL]");
                }
            }
            rowVectors.add(rowVec);
        }

        tableModel.setDataVector(rowVectors, colIdentifiers);
        rowSorter = new TableRowSorter<>(tableModel);
        dataTable.setRowSorter(rowSorter);
        applySearchFilter();

        breadcrumbLabel.setText("Database: " + currentTableMetadata.getDatabaseName() +
                " | Table: " + currentTableMetadata.getTableName() +
                " | " + visibleColumns.size() + "/" + allHeaders.size() + " Columns Visible" +
                " | " + currentFullData.getRowCount() + " Rows");

        // Set reasonable column widths
        for (int i = 0; i < dataTable.getColumnCount(); i++) {
            dataTable.getColumnModel().getColumn(i).setPreferredWidth(140);
        }
    }

    private void openColumnVisibilityDialog() {
        if (currentFullData == null) return;

        Window window = SwingUtilities.getWindowAncestor(this);
        ColumnVisibilityDialog dialog = new ColumnVisibilityDialog(
                window,
                currentFullData.getHeaders(),
                visibleColumns,
                selected -> {
                    this.visibleColumns = selected;
                    updateTableGrid();
                }
        );
        dialog.setVisible(true);
    }

    private void applySearchFilter() {
        if (rowSorter == null) return;

        String query = searchField.getText().trim();
        if (query.isEmpty()) {
            rowSorter.setRowFilter(null);
        } else {
            try {
                rowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + PatternQuote(query)));
            } catch (Exception e) {
                rowSorter.setRowFilter(null);
            }
        }
    }

    private static String PatternQuote(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ("\\.^$|?*+()[]{}".indexOf(c) != -1) {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private void onExportCsv() {
        if (currentFullData == null || currentTableMetadata == null) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Table to CSV");
        chooser.setSelectedFile(new File(currentTableMetadata.getTableName() + "_export.csv"));
        chooser.setFileFilter(new FileNameExtensionFilter("CSV Files (*.csv)", "csv"));

        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
            File outFile = chooser.getSelectedFile();
            if (!outFile.getName().toLowerCase().endsWith(".csv")) {
                outFile = new File(outFile.getParentFile(), outFile.getName() + ".csv");
            }

            try {
                List<String> exportHeaders = new ArrayList<>(visibleColumns);
                List<List<String>> exportRows = new ArrayList<>();

                int rowCount = dataTable.getRowCount();
                int colCount = dataTable.getColumnCount();

                for (int r = 0; r < rowCount; r++) {
                    List<String> row = new ArrayList<>();
                    for (int c = 0; c < colCount; c++) {
                        Object val = dataTable.getValueAt(r, c);
                        row.add(val != null ? val.toString() : "");
                    }
                    exportRows.add(row);
                }

                csvParser.exportToCsv(outFile, exportHeaders, exportRows);
                JOptionPane.showMessageDialog(this, "Table exported successfully to:\n" + outFile.getAbsolutePath(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Failed to export CSV: " + e.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private DatabaseModel getSelectedDatabaseModel() {
        int idx = dbComboBox.getSelectedIndex();
        List<DatabaseModel> allDbs = dataStore.getAllDatabases();
        if (idx >= 0 && idx < allDbs.size()) {
            return allDbs.get(idx);
        }
        return null;
    }

    public String getSelectedDatabaseName() {
        DatabaseModel db = getSelectedDatabaseModel();
        return db != null ? db.getName() : "";
    }

    public String getSelectedTableName() {
        return (String) tableComboBox.getSelectedItem();
    }

    public void clearTableView() {
        currentTableMetadata = null;
        currentFullData = null;
        visibleColumns.clear();
        tableModel.setDataVector(new Vector<>(), new Vector<>());
        breadcrumbLabel.setText("Database: [None] | Table: [None] | 0 Columns | 0 Rows");
        btnColumnVisibility.setEnabled(false);
        btnExportCsv.setEnabled(false);
        searchField.setText("");
    }
}
