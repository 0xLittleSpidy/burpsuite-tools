// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.ui;

import com.littlespidy.headerinspector.status.model.StatusEndpointRecord;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Detail table model displaying endpoints and HTTP methods returning a selected status code,
 * showing target domains and response counts.
 *
 * @author littlespidy
 */
public class StatusEndpointTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Method",
        "URL / Endpoint",
        "Domain",
        "Responses"
    };

    private final List<StatusEndpointRecord> records = new ArrayList<>();

    public void setRecords(List<StatusEndpointRecord> newRecords) {
        this.records.clear();
        if (newRecords != null) {
            this.records.addAll(newRecords);
        }
        fireTableDataChanged();
    }

    public StatusEndpointRecord getRecordAt(int rowIndex) {
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
            case 0, 1, 2 -> String.class;
            case 3 -> Integer.class;
            default -> Object.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        StatusEndpointRecord r = records.get(rowIndex);
        if (r == null) return "";
        return switch (columnIndex) {
            case 0 -> r.method();
            case 1 -> r.url();
            case 2 -> r.domain();
            case 3 -> r.occurrences();
            default -> "";
        };
    }
}
