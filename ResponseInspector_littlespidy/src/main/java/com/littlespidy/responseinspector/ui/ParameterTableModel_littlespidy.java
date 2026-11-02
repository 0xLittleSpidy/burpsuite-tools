// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import com.littlespidy.responseinspector.model.ParameterEntry_littlespidy;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying grouped parameter entries.
 */
public class ParameterTableModel_littlespidy extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#",
            "Parameter Name",
            "Source",
            "Format",
            "Occurrences",
            "Sample Values"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            Integer.class,
            String.class,
            String.class,
            String.class,
            Integer.class,
            String.class
    };

    private final List<ParameterEntry_littlespidy> entries = new ArrayList<>();

    public synchronized void setEntries(List<ParameterEntry_littlespidy> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public synchronized void clear() {
        entries.clear();
        fireTableDataChanged();
    }

    public synchronized ParameterEntry_littlespidy getEntryAt(int rowIndex) {
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
        return COLUMN_CLASSES[columnIndex];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) {
            return null;
        }
        ParameterEntry_littlespidy entry = entries.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> rowIndex + 1;
            case 1 -> entry.getName();
            case 2 -> entry.getSourceDisplay();
            case 3 -> entry.getFormatDisplay();
            case 4 -> entry.getOccurrenceCount();
            case 5 -> entry.getSampleValuesDisplay();
            default -> null;
        };
    }
}
