// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.ui;

import com.littlespidy.headerinspector.method.model.MethodEndpointRecord;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Detail table model displaying endpoints/URLs for a selected HTTP method,
 * showing target domains, associated HTTP status codes, and request counts.
 *
 * @author littlespidy
 */
public class MethodEndpointTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Method",
        "URL / Endpoint",
        "Domain",
        "Status Codes",
        "Requests"
    };

    private final List<MethodEndpointRecord> records = new ArrayList<>();

    public void setRecords(List<MethodEndpointRecord> newRecords) {
        this.records.clear();
        if (newRecords != null) {
            this.records.addAll(newRecords);
        }
        fireTableDataChanged();
    }

    public MethodEndpointRecord getRecordAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < records.size()) {
            return records.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return records.size();
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
        return switch (columnIndex) {
            case 0, 1, 2, 3 -> String.class;
            case 4 -> Integer.class;
            default -> Object.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        MethodEndpointRecord r = records.get(rowIndex);
        if (r == null) return "";
        return switch (columnIndex) {
            case 0 -> r.method();
            case 1 -> r.url();
            case 2 -> r.domain();
            case 3 -> r.statusCodesFormatted();
            case 4 -> r.occurrences();
            default -> "";
        };
    }
}
