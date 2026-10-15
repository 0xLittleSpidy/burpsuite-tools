// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;
import com.littlespidy.responseinspector.model.SecretClassificationManager;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Thread-safe table model for displaying finding entries.
 * Pin column has been removed from the table view.
 * Displays dedicated Classification column for Secrets tab.
 */
public class FindingsTableModel extends AbstractTableModel {

    private static final String[] DEFAULT_COLUMN_NAMES = {
            "#", "Method", "Status", "Finding Type", "Match Excerpt", "Location", "Length", "Content-Type", "URL", "Time"
    };

    private static final Class<?>[] DEFAULT_COLUMN_CLASSES = {
            Integer.class, String.class, Integer.class, String.class, String.class, String.class, Integer.class, String.class, String.class, String.class
    };

    private static final String[] SECRET_COLUMN_NAMES = {
            "#", "Method", "Status", "Finding Type", "Classification", "Match Excerpt", "Location", "Length", "Content-Type", "URL", "Time"
    };

    private static final Class<?>[] SECRET_COLUMN_CLASSES = {
            Integer.class, String.class, Integer.class, String.class, String.class, String.class, String.class, Integer.class, String.class, String.class, String.class
    };

    private final InspectorDataStore dataStore;
    private final FindingCategory category;
    private final SecretClassificationManager classificationManager;
    private final List<FindingEntry> entries = new ArrayList<>();

    public FindingsTableModel(InspectorDataStore dataStore) {
        this(dataStore, null, null);
    }

    public FindingsTableModel(InspectorDataStore dataStore, FindingCategory category, SecretClassificationManager classificationManager) {
        this.dataStore = dataStore;
        this.category = category;
        this.classificationManager = classificationManager;
    }

    private boolean isSecretTab() {
        return category == FindingCategory.SECRET && classificationManager != null;
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
        return isSecretTab() ? SECRET_COLUMN_NAMES.length : DEFAULT_COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return isSecretTab() ? SECRET_COLUMN_NAMES[column] : DEFAULT_COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return isSecretTab() ? SECRET_COLUMN_CLASSES[columnIndex] : DEFAULT_COLUMN_CLASSES[columnIndex];
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) {
            return null;
        }
        FindingEntry entry = entries.get(rowIndex);

        if (isSecretTab()) {
            return switch (columnIndex) {
                case 0 -> entry.id();
                case 1 -> entry.method();
                case 2 -> (int) entry.statusCode();
                case 3 -> entry.patternName();
                case 4 -> classificationManager.getEffectiveClassification(entry).getDisplayName();
                case 5 -> entry.matchValue();
                case 6 -> entry.matchLocation();
                case 7 -> entry.contentLength();
                case 8 -> entry.contentType();
                case 9 -> entry.url();
                case 10 -> entry.timeString();
                default -> "";
            };
        } else {
            return switch (columnIndex) {
                case 0 -> entry.id();
                case 1 -> entry.method();
                case 2 -> (int) entry.statusCode();
                case 3 -> entry.patternName();
                case 4 -> entry.matchValue();
                case 5 -> entry.matchLocation();
                case 6 -> entry.contentLength();
                case 7 -> entry.contentType();
                case 8 -> entry.url();
                case 9 -> entry.timeString();
                default -> "";
            };
        }
    }
}
