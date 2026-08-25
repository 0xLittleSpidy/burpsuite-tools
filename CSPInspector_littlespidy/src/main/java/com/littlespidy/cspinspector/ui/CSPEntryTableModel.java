// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.ui;

import com.littlespidy.cspinspector.model.CSPEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for individual HTTP endpoints and their associated CSP configuration.
 *
 * @author littlespidy
 */
public class CSPEntryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "#",
        "Status",
        "Method",
        "Host",
        "URL",
        "Content-Type",
        "Script-Src",
        "Frame-Ancestors",
        "Object-Src",
        "Report-Only",
        "Full CSP Header"
    };

    private final List<CSPEntry> entries = new ArrayList<>();

    public synchronized void updateData(List<CSPEntry> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public synchronized CSPEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            return entries.get(rowIndex);
        }
        return null;
    }

    public synchronized List<CSPEntry> getAllEntries() {
        return new ArrayList<>(entries);
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
        return switch (columnIndex) {
            case 0, 1 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) {
            return null;
        }

        CSPEntry entry = entries.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> entry.id();
            case 1 -> entry.statusCode();
            case 2 -> entry.method();
            case 3 -> entry.host();
            case 4 -> entry.url();
            case 5 -> entry.contentType();
            case 6 -> entry.getDirectiveString("script-src");
            case 7 -> entry.getDirectiveString("frame-ancestors");
            case 8 -> entry.getDirectiveString("object-src");
            case 9 -> (entry.cspReportOnlyHeader() != null && !entry.cspReportOnlyHeader().isEmpty()) ? entry.cspReportOnlyHeader() : "";
            case 10 -> entry.getPrimaryCsp();
            default -> null;
        };
    }
}
