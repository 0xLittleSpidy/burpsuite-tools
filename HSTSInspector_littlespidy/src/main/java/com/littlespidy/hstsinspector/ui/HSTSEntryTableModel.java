// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.ui;

import com.littlespidy.hstsinspector.model.HSTSEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for individual HTTP endpoints and their HSTS configuration.
 *
 * @author littlespidy
 */
public class HSTSEntryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "#",
        "Status",
        "Method",
        "Host",
        "URL",
        "Content-Type",
        "max-age",
        "includeSubDomains",
        "preload",
        "Assessment",
        "Raw HSTS Header"
    };

    private final List<HSTSEntry> entries = new ArrayList<>();

    public synchronized void updateData(List<HSTSEntry> newEntries) {
        entries.clear();
        if (newEntries != null) entries.addAll(newEntries);
        fireTableDataChanged();
    }

    public synchronized HSTSEntry getEntryAt(int row) {
        return (row >= 0 && row < entries.size()) ? entries.get(row) : null;
    }

    public synchronized List<HSTSEntry> getAllEntries() { return new ArrayList<>(entries); }

    @Override public synchronized int getRowCount()  { return entries.size(); }
    @Override public int getColumnCount()            { return COLUMN_NAMES.length; }
    @Override public String getColumnName(int col)   { return COLUMN_NAMES[col]; }

    @Override
    public Class<?> getColumnClass(int col) {
        return (col == 0 || col == 1) ? Integer.class : String.class;
    }

    @Override
    public synchronized Object getValueAt(int row, int col) {
        if (row < 0 || row >= entries.size()) return null;
        HSTSEntry e = entries.get(row);
        return switch (col) {
            case 0  -> e.id();
            case 1  -> e.statusCode();
            case 2  -> e.method();
            case 3  -> e.host();
            case 4  -> e.url();
            case 5  -> e.contentType();
            case 6  -> e.isMissingHsts() ? "(missing)" : e.maxAge() < 0 ? "(not set)" : String.valueOf(e.maxAge()) + "s (" + e.maxAgeSummary() + ")";
            case 7  -> e.isMissingHsts() ? "(missing)" : e.includeSubDomains() ? "✔ yes" : "✘ no";
            case 8  -> e.isMissingHsts() ? "(missing)" : e.preload() ? "✔ yes" : "✘ no";
            case 9  -> e.assessment();
            case 10 -> e.isMissingHsts() ? "" : e.hstsHeader();
            default -> null;
        };
    }
}
