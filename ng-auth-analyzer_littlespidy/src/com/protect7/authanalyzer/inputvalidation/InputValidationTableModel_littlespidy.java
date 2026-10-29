// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.inputvalidation;

import java.util.ArrayList;
import java.util.List;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

/**
 * Table model for displaying Input Validation parameter fuzz probe results.
 */
public class InputValidationTableModel_littlespidy extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private final List<InputValidationTestResult_littlespidy> results = new ArrayList<>();

    private static final String[] COLUMN_NAMES = {
            "ID", "Method", "Host", "Path", "Category", "Parameter",
            "Type", "Payload", "Status", "Length", "Diff %", "Findings / Anomaly"
    };

    public synchronized void addResult(InputValidationTestResult_littlespidy result) {
        if (result == null) return;
        results.add(result);
        int idx = results.size() - 1;
        if (SwingUtilities.isEventDispatchThread()) {
            fireTableRowsInserted(idx, idx);
        } else {
            SwingUtilities.invokeLater(() -> fireTableRowsInserted(idx, idx));
        }
    }

    public synchronized void addResults(List<InputValidationTestResult_littlespidy> newResults) {
        if (newResults == null || newResults.isEmpty()) return;
        int start = results.size();
        results.addAll(newResults);
        int end = results.size() - 1;
        if (SwingUtilities.isEventDispatchThread()) {
            fireTableRowsInserted(start, end);
        } else {
            SwingUtilities.invokeLater(() -> fireTableRowsInserted(start, end));
        }
    }

    public synchronized void clear() {
        results.clear();
        if (SwingUtilities.isEventDispatchThread()) {
            fireTableDataChanged();
        } else {
            SwingUtilities.invokeLater(this::fireTableDataChanged);
        }
    }

    public synchronized InputValidationTestResult_littlespidy getResult(int row) {
        if (row >= 0 && row < results.size()) {
            return results.get(row);
        }
        return null;
    }

    public synchronized List<InputValidationTestResult_littlespidy> getAllResults() {
        return new ArrayList<>(results);
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
            case 8:
            case 9:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        InputValidationTestResult_littlespidy res = getResult(rowIndex);
        if (res == null) return null;
        switch (columnIndex) {
            case 0: return res.getId();
            case 1: return res.getMethod();
            case 2: return res.getHost();
            case 3: return res.getPath();
            case 4: return res.getCategory();
            case 5: return res.getParameterName();
            case 6: return res.getParameterType();
            case 7: {
                String val = res.getPayloadValue();
                if (val.isEmpty()) return "\"\" (empty)";
                return val.length() > 30 ? val.substring(0, 30) + "..." : val;
            }
            case 8: return res.getStatusCode();
            case 9: return res.getLength();
            case 10: {
                int diff = res.getSizeDiffPercent();
                return (diff >= 0 ? "+" : "") + diff + "%";
            }
            case 11: return res.getAnomalyType();
            default: return "";
        }
    }
}
