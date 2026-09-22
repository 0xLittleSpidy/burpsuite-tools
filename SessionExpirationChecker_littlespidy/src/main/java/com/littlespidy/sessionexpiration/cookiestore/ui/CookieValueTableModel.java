// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.ui;

import com.littlespidy.sessionexpiration.cookiestore.model.CookieValueRecord;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model displaying unique cookie values under a selected cookie name,
 * with repetition count (how many times repeated), domains, security attributes, and sample URL.
 *
 * @author littlespidy
 */
public class CookieValueTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "#", "Cookie Value", "Repeated (Count)", "Domains", "Attributes / Flags", "Method", "URL", "Status"
    };

    private List<CookieValueRecord> displayedRecords = new ArrayList<>();

    public void setRecords(List<CookieValueRecord> records) {
        this.displayedRecords = (records != null) ? new ArrayList<>(records) : new ArrayList<>();
        fireTableDataChanged();
    }

    public CookieValueRecord getRecordAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayedRecords.size()) {
            return displayedRecords.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return displayedRecords.size();
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
            case 2:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        CookieValueRecord record = getRecordAt(rowIndex);
        if (record == null) return null;

        switch (columnIndex) {
            case 0: return rowIndex + 1;
            case 1: return record.value();
            case 2: return record.occurrences();
            case 3: return record.domainsFormatted();
            case 4: return record.attributes();
            case 5: return record.sampleMethod();
            case 6: return record.sampleUrl();
            case 7: return (record.sampleStatusCode() > 0) ? record.sampleStatusCode() : "";
            default: return "";
        }
    }
}
