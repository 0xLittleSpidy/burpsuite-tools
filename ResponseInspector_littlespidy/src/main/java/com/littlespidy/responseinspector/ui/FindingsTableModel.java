// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Thread-safe table model for displaying finding entries.
 */
public class FindingsTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#", "Pin", "Method", "Status", "Finding Type", "Match Excerpt", "Location", "Length", "Content-Type", "URL", "Time"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            Integer.class, String.class, String.class, Integer.class, String.class, String.class, String.class, Integer.class, String.class, String.class, String.class
    };

    private final InspectorDataStore dataStore;
    private final List<FindingEntry> entries = new ArrayList<>();

    public FindingsTableModel(InspectorDataStore dataStore) {
        this.dataStore = dataStore;
    }

    public synchronized void setEntries(List<FindingEntry> newEntries) {
        this.entries.clear();
        if (newEntries != null) {
            this.entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public synchronized FindingEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            return entries.get(rowIndex);
        }
        return null;
    }

    @Override
    public synchronized int getRowCount() {
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
        return COLUMN_CLASSES[columnIndex];
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) {
            return null;
        }
        FindingEntry entry = entries.get(rowIndex);
        boolean pinned = dataStore.isPinned(entry.id());

        return switch (columnIndex) {
            case 0 -> entry.id();
            case 1 -> pinned ? "\uD83D\uDCCC" : "";
            case 2 -> entry.method();
            case 3 -> (int) entry.statusCode();
            case 4 -> entry.patternName();
            case 5 -> entry.matchValue();
            case 6 -> entry.matchLocation();
            case 7 -> entry.contentLength();
            case 8 -> entry.contentType();
            case 9 -> entry.url();
            case 10 -> entry.timeString();
            default -> "";
        };
    }
}
