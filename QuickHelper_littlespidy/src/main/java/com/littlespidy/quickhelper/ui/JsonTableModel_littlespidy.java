// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Dynamic table model supporting arbitrary JSON columns and rows.
 */
public class JsonTableModel_littlespidy extends AbstractTableModel {

    private final List<String> columnNames = new ArrayList<>();
    private final List<List<String>> rows = new ArrayList<>();

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.size();
    }

    @Override
    public String getColumnName(int column) {
        if (column >= 0 && column < columnNames.size()) {
            return columnNames.get(column);
        }
        return "";
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= rows.size()) {
            return null;
        }
        List<String> row = rows.get(rowIndex);
        if (columnIndex < 0 || columnIndex >= row.size()) {
            return "";
        }
        return row.get(columnIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    public synchronized void setTableData(List<String> cols, List<List<String>> newRows) {
        columnNames.clear();
        rows.clear();

        if (cols != null) {
            columnNames.addAll(cols);
        }
        if (newRows != null) {
            for (List<String> r : newRows) {
                rows.add(new ArrayList<>(r));
            }
        }
        fireTableStructureChanged();
    }

    public synchronized void clear() {
        columnNames.clear();
        rows.clear();
        fireTableStructureChanged();
    }

    public synchronized List<String> getRowValues(int modelRow) {
        if (modelRow >= 0 && modelRow < rows.size()) {
            return Collections.unmodifiableList(rows.get(modelRow));
        }
        return Collections.emptyList();
    }

    public synchronized List<String> getColumnNames() {
        return Collections.unmodifiableList(columnNames);
    }

    public synchronized List<List<String>> getAllRows() {
        return Collections.unmodifiableList(rows);
    }
}
