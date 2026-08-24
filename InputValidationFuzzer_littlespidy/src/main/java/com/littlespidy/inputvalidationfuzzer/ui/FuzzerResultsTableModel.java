package com.littlespidy.inputvalidationfuzzer.ui;

import com.littlespidy.inputvalidationfuzzer.model.FuzzResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe table model maintaining both complete and filtered fuzzer results.
 *
 * @author littlespidy
 */
public class FuzzerResultsTableModel extends AbstractTableModel {
    private final String[] columnNames = {
        "#", "Parameter", "Type", "Payload Name", "Payload Value", "Base Status", "Status", "Base Len", "Length", "Content-Type", "Signal", "Severity"
    };

    private final Class<?>[] columnClasses = {
        Integer.class, String.class, String.class, String.class, String.class, Integer.class, Integer.class, Integer.class, Integer.class, String.class, String.class, String.class
    };

    private final List<FuzzResult> allResults = new ArrayList<>();
    private final List<FuzzResult> filteredResults = new ArrayList<>();
    private Predicate<FuzzResult> currentFilter = result -> true;

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

        FuzzResult res = filteredResults.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> res.id();
            case 1 -> res.parameterName();
            case 2 -> res.parameterType();
            case 3 -> res.payloadName();
            case 4 -> res.payloadValue();
            case 5 -> res.baseStatus();
            case 6 -> res.responseStatus();
            case 7 -> res.baseLength();
            case 8 -> res.responseLength();
            case 9 -> res.responseContentType();
            case 10 -> res.signal();
            case 11 -> res.issueSeverity();
            default -> null;
        };
    }

    public synchronized FuzzResult getResultAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < filteredResults.size()) {
            return filteredResults.get(rowIndex);
        }
        return null;
    }

    public synchronized void addResult(FuzzResult result) {
        allResults.add(result);
        if (currentFilter.test(result)) {
            filteredResults.add(result);
            int row = filteredResults.size() - 1;
            fireTableRowsInserted(row, row);
        }
    }

    public synchronized void setFilter(Predicate<FuzzResult> filter) {
        this.currentFilter = (filter != null) ? filter : r -> true;
        filteredResults.clear();
        for (FuzzResult res : allResults) {
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

    public synchronized List<FuzzResult> getFilteredResults() {
        return new ArrayList<>(filteredResults);
    }

    public synchronized List<FuzzResult> getAllResults() {
        return new ArrayList<>(allResults);
    }
}
