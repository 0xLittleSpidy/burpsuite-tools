// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import com.littlespidy.gwtmap.model.GwtHttpHistoryEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying all HTTP requests and responses executed by GWTMap.
 *
 * @author littlespidy
 */
public class GwtHttpHistoryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#", "Time", "Type", "Method", "URL", "Status", "Length", "Duration"
    };

    private final List<GwtHttpHistoryEntry> entries = new ArrayList<>();

    public synchronized void setEntries(List<GwtHttpHistoryEntry> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public synchronized void addEntry(GwtHttpHistoryEntry entry) {
        if (entry != null) {
            entries.add(entry);
            int row = entries.size() - 1;
            fireTableRowsInserted(row, row);
        }
    }

    public synchronized void clear() {
        entries.clear();
        fireTableDataChanged();
    }

    public synchronized GwtHttpHistoryEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            return entries.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return entries.size();
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
            case 5:
            case 6:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        GwtHttpHistoryEntry entry = getEntryAt(rowIndex);
        if (entry == null) return "";

        switch (columnIndex) {
            case 0: return entry.getId();
            case 1: return entry.getTimestamp();
            case 2: return entry.getType();
            case 3: return entry.getMethod();
            case 4: return entry.getUrl();
            case 5: return entry.getStatusCode() > 0 ? entry.getStatusCode() : "";
            case 6: return entry.getResponseLength() >= 0 ? entry.getResponseLength() : "";
            case 7: return entry.getDurationMs() >= 0 ? entry.getDurationMs() + " ms" : "";
            default: return "";
        }
    }
}
