// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.ProbeResult_littlespidy;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying API version probing results with typed columns for numerical sorting.
 */
public class VersionResultsTableModel_littlespidy extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#",
            "Strategy",
            "Variation / Mutation",
            "Status",
            "Length (Bytes)",
            "MIME Type",
            "Diff Analysis",
            "Latency (ms)"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            Integer.class,
            String.class,
            String.class,
            Integer.class,
            Integer.class,
            String.class,
            String.class,
            Long.class
    };

    private final List<ProbeResult_littlespidy> results = new ArrayList<>();

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMN_NAMES[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_CLASSES[columnIndex];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= results.size()) {
            return null;
        }
        ProbeResult_littlespidy r = results.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> r.getId();
            case 1 -> r.getStrategyName();
            case 2 -> r.getVariation();
            case 3 -> r.getStatusCode();
            case 4 -> r.getResponseLength();
            case 5 -> r.getMimeType();
            case 6 -> r.getDiffAnalysis();
            case 7 -> r.getLatencyMs();
            default -> null;
        };
    }

    public synchronized void addResult(ProbeResult_littlespidy result) {
        int index = results.size();
        results.add(result);
        fireTableRowsInserted(index, index);
    }

    public synchronized void clear() {
        int size = results.size();
        if (size > 0) {
            results.clear();
            fireTableRowsDeleted(0, size - 1);
        }
    }

    public synchronized ProbeResult_littlespidy getResultAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < results.size()) {
            return results.get(rowIndex);
        }
        return null;
    }

    public synchronized List<ProbeResult_littlespidy> getAllResults() {
        return new ArrayList<>(results);
    }
}
