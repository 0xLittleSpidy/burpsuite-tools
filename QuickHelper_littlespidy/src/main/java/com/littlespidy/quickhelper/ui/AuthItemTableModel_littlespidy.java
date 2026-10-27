// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import com.littlespidy.quickhelper.model.AuthItem_littlespidy;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying extracted authentication tokens, headers, and cookies.
 */
public class AuthItemTableModel_littlespidy extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "Type",
            "Name / Key",
            "Length",
            "Value Preview"
    };

    private final List<AuthItem_littlespidy> items = new ArrayList<>();

    @Override
    public int getRowCount() {
        return items.size();
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
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= items.size()) {
            return null;
        }

        AuthItem_littlespidy item = items.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return item.getType();
            case 1:
                return item.getName();
            case 2:
                return item.getLength() + " chars";
            case 3:
                return item.getValue();
            default:
                return null;
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    public synchronized void setItems(List<AuthItem_littlespidy> newItems) {
        items.clear();
        if (newItems != null) {
            items.addAll(newItems);
        }
        fireTableDataChanged();
    }

    public synchronized void clear() {
        items.clear();
        fireTableDataChanged();
    }

    public synchronized AuthItem_littlespidy getItem(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < items.size()) {
            return items.get(rowIndex);
        }
        return null;
    }

    public synchronized List<AuthItem_littlespidy> getAllItems() {
        return new ArrayList<>(items);
    }
}
