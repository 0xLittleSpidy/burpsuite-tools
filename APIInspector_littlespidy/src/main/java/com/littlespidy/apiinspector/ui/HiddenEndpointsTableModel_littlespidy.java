// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Table model for managing saved endpoints in Hidden API Storage.
 * Supports inline editing of the Source column via dropdown and Notes column.
 */
public class HiddenEndpointsTableModel_littlespidy extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#",
            "Source",
            "Method",
            "Endpoint / URL",
            "Parameters",
            "Status",
            "Date Added",
            "Notes"
    };

    private final List<HiddenEndpoint_littlespidy> endpoints = new ArrayList<>();
    private Runnable onStateChanged;

    public void setOnStateChanged(Runnable callback) {
        this.onStateChanged = callback;
    }

    private void notifyChanged() {
        if (onStateChanged != null) {
            onStateChanged.run();
        }
    }

    @Override
    public int getRowCount() {
        return endpoints.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        if (column >= 0 && column < COLUMN_NAMES.length) {
            return COLUMN_NAMES[column];
        }
        return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> Integer.class;
            case 5 -> String.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        // Source (column 1) and Notes (column 7) are editable
        return columnIndex == 1 || columnIndex == 7;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= endpoints.size()) {
            return null;
        }
        HiddenEndpoint_littlespidy ep = endpoints.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> rowIndex + 1;
            case 1 -> ep.getSource();
            case 2 -> ep.getMethod();
            case 3 -> (ep.getUrl() != null && !ep.getUrl().isBlank()) ? ep.getUrl() : ep.getPath();
            case 4 -> ep.getParametersSummary();
            case 5 -> ep.getStatusCode() > 0 ? String.valueOf(ep.getStatusCode()) : "-";
            case 6 -> ep.getFormattedDate();
            case 7 -> ep.getNotes();
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= endpoints.size() || aValue == null) {
            return;
        }
        HiddenEndpoint_littlespidy ep = endpoints.get(rowIndex);
        if (columnIndex == 1) {
            ep.setSource(aValue.toString());
            fireTableCellUpdated(rowIndex, columnIndex);
            notifyChanged();
        } else if (columnIndex == 7) {
            ep.setNotes(aValue.toString());
            fireTableCellUpdated(rowIndex, columnIndex);
            notifyChanged();
        }
    }

    public synchronized void addEndpoint(HiddenEndpoint_littlespidy ep) {
        if (ep == null) return;
        endpoints.add(0, ep);
        fireTableRowsInserted(0, 0);
        notifyChanged();
    }

    public synchronized void addEndpoints(List<HiddenEndpoint_littlespidy> newEndpoints) {
        if (newEndpoints == null || newEndpoints.isEmpty()) return;
        endpoints.addAll(0, newEndpoints);
        fireTableDataChanged();
        notifyChanged();
    }

    public synchronized HiddenEndpoint_littlespidy removeEndpoint(int index) {
        if (index >= 0 && index < endpoints.size()) {
            HiddenEndpoint_littlespidy removed = endpoints.remove(index);
            fireTableRowsDeleted(index, index);
            notifyChanged();
            return removed;
        }
        return null;
    }

    public synchronized void clear() {
        endpoints.clear();
        fireTableDataChanged();
        notifyChanged();
    }

    public synchronized HiddenEndpoint_littlespidy getEndpointAt(int index) {
        if (index >= 0 && index < endpoints.size()) {
            return endpoints.get(index);
        }
        return null;
    }

    public synchronized List<HiddenEndpoint_littlespidy> getAllEndpoints() {
        return Collections.unmodifiableList(new ArrayList<>(endpoints));
    }

    public synchronized void setEndpoints(List<HiddenEndpoint_littlespidy> list) {
        endpoints.clear();
        if (list != null) {
            endpoints.addAll(list);
        }
        fireTableDataChanged();
        notifyChanged();
    }
}
