// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import com.littlespidy.gwtmap.model.GwtProxyHistoryEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying Burp Suite HTTP Proxy history entries enriched with GWT RPC metadata.
 *
 * @author littlespidy
 */
public class GwtProxyHistoryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#", "Time", "Method", "Method Name", "Service", "URL", "Status", "Length", "MIME Type", "Duration"
    };

    private final List<GwtProxyHistoryEntry> entries = new ArrayList<>();

    public synchronized void setEntries(List<GwtProxyHistoryEntry> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public synchronized void addEntry(GwtProxyHistoryEntry entry) {
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

    public synchronized GwtProxyHistoryEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            return entries.get(rowIndex);
        }
        return null;
    }

    public synchronized List<GwtProxyHistoryEntry> getAllEntries() {
        return new ArrayList<>(entries);
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
            case 6:
            case 7:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        GwtProxyHistoryEntry entry = getEntryAt(rowIndex);
        if (entry == null) return "";

        switch (columnIndex) {
            case 0: return entry.getId();
            case 1: return entry.getTimestamp();
            case 2: return entry.getHttpMethod();
            case 3: return entry.getMethodName();
            case 4: return entry.getService();
            case 5: return entry.getUrl();
            case 6: return entry.getStatusCode() > 0 ? entry.getStatusCode() : "";
            case 7: return entry.getResponseLength() >= 0 ? entry.getResponseLength() : "";
            case 8: return entry.getMimeType();
            case 9: return entry.getDurationMs() >= 0 ? entry.getDurationMs() + " ms" : "-";
            default: return "";
        }
    }
}
