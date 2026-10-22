// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.hsts.ui;

import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.hsts.model.HSTSEntry;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Table model for the top "HSTS Value Overview & Assessment" summary table.
 * Displays all domain names and their associated values, where every value has
 * its own separate row, URL count, and assessment.
 *
 * @author littlespidy
 */
public class HSTSSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = { "Domain Name", "Value", "URL Count", "Assessment" };

    public static class SummaryRow {
        private final String domain;
        private final String value;
        private final int urlCount;
        private final String assessment;
        private final List<HSTSEntry> entries;

        public SummaryRow(String domain, String value, int urlCount, String assessment, List<HSTSEntry> entries) {
            this.domain = domain;
            this.value = value;
            this.urlCount = urlCount;
            this.assessment = assessment;
            this.entries = entries;
        }

        public String getDomain() { return domain; }
        public String getValue() { return value; }
        public int getUrlCount() { return urlCount; }
        public String getAssessment() { return assessment; }
        public List<HSTSEntry> getEntries() { return entries; }
    }

    private final List<SummaryRow> rows = new ArrayList<>();

    public synchronized void updateData(List<HSTSEntry> entries, String mode) {
        rows.clear();
        if (entries == null || entries.isEmpty()) {
            fireTableDataChanged();
            return;
        }

        Map<String, List<HSTSEntry>> map = new LinkedHashMap<>();
        for (HSTSEntry entry : entries) {
            String domain = (entry.host() != null && !entry.host().isBlank()) ? entry.host().trim() : "(unknown)";
            String val = deriveValue(entry, mode);
            String groupKey = domain.toLowerCase() + "\t" + val;
            map.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(entry);
        }

        for (List<HSTSEntry> groupList : map.values()) {
            HSTSEntry first = groupList.get(0);
            String domain = (first.host() != null && !first.host().isBlank()) ? first.host().trim() : "(unknown)";
            String val = deriveValue(first, mode);
            int count = groupList.size();
            String assessment = first.assessment();
            rows.add(new SummaryRow(domain, val, count, assessment, groupList));
        }

        rows.sort(Comparator.comparing((SummaryRow r) -> r.getDomain().toLowerCase())
                .thenComparing(SummaryRow::getValue));
        fireTableDataChanged();
    }

    private static String deriveValue(HSTSEntry e, String mode) {
        if (e.isMissingHsts()) return "(missing HSTS)";
        if (mode == null) return e.hstsHeader().trim();
        return switch (mode) {
            case HSTSDataStore.MODE_MAX_AGE -> e.maxAge() < 0 ? "(not set)" : "max-age=" + e.maxAge() + " (" + e.maxAgeSummary() + ")";
            case HSTSDataStore.MODE_SUBDOMAINS -> e.includeSubDomains() ? "includeSubDomains: present" : "includeSubDomains: absent";
            case HSTSDataStore.MODE_PRELOAD -> e.preload() ? "preload: present" : "preload: absent";
            case HSTSDataStore.MODE_MISSING -> "(missing HSTS)";
            default -> e.hstsHeader().trim();
        };
    }

    public synchronized SummaryRow getRowAt(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return null;
        return rows.get(modelRow);
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
            case 0 -> r.getDomain();
            case 1 -> r.getValue();
            case 2 -> r.getUrlCount();
            case 3 -> r.getAssessment();
            default -> null;
        };
    }
}
