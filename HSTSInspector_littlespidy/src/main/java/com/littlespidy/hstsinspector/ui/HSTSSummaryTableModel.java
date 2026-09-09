// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.ui;

import com.littlespidy.hstsinspector.model.HSTSEntry;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Table model for the top "HSTS Value Overview & Assessment" summary table.
 * Each row represents a unique header pattern/value, associated domains, and occurrence count.
 *
 * @author littlespidy
 */
public class HSTSSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = { "Value", "Domains", "Count", "Assessment" };

    public static class SummaryRow {
        private final String value;
        private final String domains;
        private final int count;
        private final String assessment;
        private final String groupKey;

        public SummaryRow(String value, String domains, int count, String assessment, String groupKey) {
            this.value = value;
            this.domains = domains;
            this.count = count;
            this.assessment = assessment;
            this.groupKey = groupKey;
        }

        public String getValue() { return value; }
        public String getDomains() { return domains; }
        public int getCount() { return count; }
        public String getAssessment() { return assessment; }
        public String getGroupKey() { return groupKey; }
    }

    private final List<SummaryRow> rows = new ArrayList<>();

    public synchronized void updateData(Map<String, List<HSTSEntry>> grouped) {
        rows.clear();
        for (Map.Entry<String, List<HSTSEntry>> e : grouped.entrySet()) {
            String groupKey   = e.getKey();
            List<HSTSEntry> entries = e.getValue();
            int count         = entries.size();

            // Collect distinct domains (hosts)
            Set<String> domainSet = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            for (HSTSEntry entry : entries) {
                if (entry.host() != null && !entry.host().isBlank()) {
                    domainSet.add(entry.host());
                }
            }
            String domains = String.join(", ", domainSet);

            // Raw header value
            String rawValue;
            if (entries.isEmpty()) {
                rawValue = groupKey;
            } else {
                HSTSEntry first = entries.get(0);
                rawValue = first.isMissingHsts() ? "(missing HSTS)" : first.hstsHeader().trim();
            }

            String assessment = entries.isEmpty() ? "" : entries.get(0).assessment();
            rows.add(new SummaryRow(rawValue, domains, count, assessment, groupKey));
        }
        // Sort: CRITICAL → HIGH → MEDIUM → GOOD → others
        rows.sort(Comparator.comparingInt(r -> severityOrder(r.getAssessment())));
        fireTableDataChanged();
    }

    public synchronized String getSummaryValueAt(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return null;
        return rows.get(modelRow).getGroupKey();
    }

    @Override public synchronized int getRowCount()  { return rows.size(); }
    @Override public int getColumnCount()            { return COLUMNS.length; }
    @Override public String getColumnName(int col)   { return COLUMNS[col]; }

    @Override
    public Class<?> getColumnClass(int col) {
        return col == 2 ? Integer.class : String.class;
    }

    @Override
    public synchronized Object getValueAt(int row, int col) {
        if (row < 0 || row >= rows.size()) return null;
        SummaryRow r = rows.get(row);
        return switch (col) {
            case 0 -> r.getValue();
            case 1 -> r.getDomains();
            case 2 -> r.getCount();
            case 3 -> r.getAssessment();
            default -> null;
        };
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
