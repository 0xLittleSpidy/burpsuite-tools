// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.ui;

import com.littlespidy.activescansessionkeeper.model.ScanActivityEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying live scan activity entries, intercepted requests, and expiration events.
 *
 * @author littlespidy
 */
public class ActivityTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "#", "Time", "Tool", "Method", "Host", "URL", "Status", "Event", "Details"
    };

    private List<ScanActivityEntry> displayedEntries = new ArrayList<>();

    public void setEntries(List<ScanActivityEntry> entries) {
        this.displayedEntries = (entries != null) ? new ArrayList<>(entries) : new ArrayList<>();
        fireTableDataChanged();
    }

    public ScanActivityEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayedEntries.size()) {
            return displayedEntries.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return displayedEntries.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMNS[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
            case 6:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ScanActivityEntry entry = getEntryAt(rowIndex);
        if (entry == null) return null;

        switch (columnIndex) {
            case 0: return (int) entry.getId();
            case 1: return entry.getTimestamp();
            case 2: return entry.getTool();
            case 3: return entry.getMethod();
            case 4: return entry.getHost();
            case 5: return entry.getUrl();
            case 6: return (entry.getStatusCode() > 0) ? entry.getStatusCode() : "";
            case 7: return entry.getEventType();
            case 8: return entry.getDetails();
            default: return "";
        }
    }
}
