// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.ui;

import com.littlespidy.headerinspector.collector.model.HeaderValueRecord;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Detail table model displaying unique values for a selected HTTP header name,
 * with associated domains, occurrence counts, and sample request attributes.
 *
 * @author littlespidy
 */
public class HeaderValueTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Unique Value",
        "Associated Domains",
        "Count",
        "Sample Method",
        "Sample Status",
        "Sample URL"
    };

    private final List<HeaderValueRecord> records = new ArrayList<>();

    public void setRecords(List<HeaderValueRecord> newRecords) {
        this.records.clear();
        if (newRecords != null) {
            this.records.addAll(newRecords);
        }
        fireTableDataChanged();
    }

    public HeaderValueRecord getRecordAt(int rowIndex) {
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
            case 0, 1, 3, 5 -> String.class;
            case 2, 4 -> Integer.class;
            default -> Object.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        HeaderValueRecord r = records.get(rowIndex);
        if (r == null) return "";
        return switch (columnIndex) {
            case 0 -> r.value();
            case 1 -> r.domainsFormatted();
            case 2 -> r.occurrences();
            case 3 -> r.sampleMethod();
            case 4 -> r.sampleStatusCode() > 0 ? r.sampleStatusCode() : "";
            case 5 -> r.sampleUrl();
            default -> "";
        };
    }
}
