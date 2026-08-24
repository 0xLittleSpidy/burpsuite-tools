// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.ui;

import com.littlespidy.cacheheaderinspector.model.CacheEntry;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Table model displaying grouped cache directive values and the count of associated URLs.
 * Synchronized for thread-safe UI updates.
 *
 * @author littlespidy
 */
public class CacheSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Cache Directive Value",
        "URL Count"
    };

    private final List<Map.Entry<String, List<CacheEntry>>> rows = new ArrayList<>();

    public synchronized void updateData(Map<String, List<CacheEntry>> groupedData) {
        rows.clear();
        if (groupedData != null) {
            // Sort by URL count descending by default
            List<Map.Entry<String, List<CacheEntry>>> sortedEntries = new ArrayList<>(groupedData.entrySet());
            sortedEntries.sort((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()));
            rows.addAll(sortedEntries);
        }
        fireTableDataChanged();
    }

    public synchronized String getDirectiveValueAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return rows.get(rowIndex).getKey();
        }
        return null;
    }

    public synchronized List<CacheEntry> getEntriesAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return new ArrayList<>(rows.get(rowIndex).getValue());
        }
        return Collections.emptyList();
    }

    public synchronized int getTotalUrlCount() {
        int total = 0;
        for (Map.Entry<String, List<CacheEntry>> entry : rows) {
            total += entry.getValue().size();
        }
        return total;
    }

    @Override
    public synchronized int getRowCount() {
        return rows.size();
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
        return switch (columnIndex) {
            case 0 -> String.class;
            case 1 -> Integer.class;
            default -> Object.class;
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= rows.size()) {
            return null;
        }

        Map.Entry<String, List<CacheEntry>> row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.getKey();
            case 1 -> row.getValue().size();
            default -> null;
        };
    }
}
