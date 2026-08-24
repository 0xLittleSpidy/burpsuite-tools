package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.model.ConversionResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe table model maintaining both complete and filtered POST to GET conversion results.
 *
 * @author littlespidy
 */
public class ConversionResultsTableModel extends AbstractTableModel {
    private final String[] columnNames = {
        "#", "Method", "URL", "Path", "POST Status", "GET Status", "POST Len", "GET Len", "Content-Type", "Signal", "Severity"
    };

    private final Class<?>[] columnClasses = {
        Integer.class, String.class, String.class, String.class, Integer.class, Integer.class, Integer.class, Integer.class, String.class, String.class, String.class
    };

    private final List<ConversionResult> allResults = new ArrayList<>();
    private final List<ConversionResult> filteredResults = new ArrayList<>();
    private Predicate<ConversionResult> currentFilter = r -> true;

    @Override
    public synchronized int getRowCount() {
        return filteredResults.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnClasses[columnIndex];
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= filteredResults.size()) {
            return null;
        }

        ConversionResult res = filteredResults.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> res.id();
            case 1 -> res.method();
            case 2 -> res.url();
            case 3 -> res.path();
            case 4 -> res.baseStatus();
            case 5 -> res.getStatus();
            case 6 -> res.baseLength();
            case 7 -> res.getLength();
            case 8 -> res.getContentType();
            case 9 -> res.signal();
            case 10 -> res.severity();
            default -> null;
        };
    }

    public synchronized ConversionResult getResultAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < filteredResults.size()) {
            return filteredResults.get(rowIndex);
        }
        return null;
    }

    public synchronized void addResult(ConversionResult result) {
        allResults.add(result);
        if (currentFilter.test(result)) {
            filteredResults.add(result);
            int row = filteredResults.size() - 1;
            fireTableRowsInserted(row, row);
        }
    }

    public synchronized void setFilter(Predicate<ConversionResult> filter) {
        this.currentFilter = (filter != null) ? filter : r -> true;
        filteredResults.clear();
        for (ConversionResult res : allResults) {
            if (currentFilter.test(res)) {
                filteredResults.add(res);
            }
        }
        fireTableDataChanged();
    }

    public synchronized void clear() {
        allResults.clear();
        filteredResults.clear();
        fireTableDataChanged();
    }

    public synchronized int getAllResultsCount() {
        return allResults.size();
    }

    public synchronized List<ConversionResult> getFilteredResults() {
        return new ArrayList<>(filteredResults);
    }

    public synchronized List<ConversionResult> getAllResults() {
        return new ArrayList<>(allResults);
    }
}
