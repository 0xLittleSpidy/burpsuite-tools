// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.ui;

import com.littlespidy.hstsinspector.model.HSTSEntry;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Table model for the top "HSTS Value Overview & Assessment" summary table.
 * Each row represents a unique header pattern/value and its occurrence count.
 *
 * @author littlespidy
 */
public class HSTSSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = { "HSTS Value / Pattern", "Count", "Assessment" };

    // Ordered list of (value, count, assessment) rows
    private final List<String[]> rows = new ArrayList<>();

    public synchronized void updateData(Map<String, List<HSTSEntry>> grouped) {
        rows.clear();
        for (Map.Entry<String, List<HSTSEntry>> e : grouped.entrySet()) {
            String pattern    = e.getKey();
            int count         = e.getValue().size();
            String assessment = e.getValue().isEmpty() ? "" : e.getValue().get(0).assessment();
            rows.add(new String[]{ pattern, String.valueOf(count), assessment });
        }
        // Sort: CRITICAL → HIGH → MEDIUM → GOOD → others
        rows.sort(Comparator.comparingInt(r -> severityOrder(r[2])));
        fireTableDataChanged();
    }

    public synchronized String getSummaryValueAt(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return null;
        return rows.get(modelRow)[0];
    }

    @Override public synchronized int getRowCount()  { return rows.size(); }
    @Override public int getColumnCount()            { return COLUMNS.length; }
    @Override public String getColumnName(int col)   { return COLUMNS[col]; }

    @Override
    public Class<?> getColumnClass(int col) {
        return col == 1 ? Integer.class : String.class;
    }

    @Override
    public synchronized Object getValueAt(int row, int col) {
        if (row < 0 || row >= rows.size()) return null;
        return col == 1 ? Integer.parseInt(rows.get(row)[1]) : rows.get(row)[col];
    }

    private static int severityOrder(String assessment) {
        if (assessment == null) return 99;
        String a = assessment.toUpperCase();
        if (a.startsWith("CRITICAL")) return 0;
        if (a.startsWith("HIGH"))     return 1;
        if (a.startsWith("MEDIUM"))   return 2;
        if (a.startsWith("GOOD"))     return 3;
        return 4;
    }
}
