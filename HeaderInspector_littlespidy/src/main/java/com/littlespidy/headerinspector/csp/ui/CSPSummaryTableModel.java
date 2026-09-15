// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.ui;

import com.littlespidy.headerinspector.csp.model.CSPEntry;
import com.littlespidy.headerinspector.csp.evaluator.CspFinding;
import com.littlespidy.headerinspector.csp.evaluator.GoogleCspEvaluator;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Summary table model showing unique CSP values, associated domains, counts, and security assessments.
 *
 * @author littlespidy
 */
public class CSPSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Value",
        "Domains",
        "Count",
        "Assessment"
    };

    public static class CSPSummaryRow {
        private final String value;
        private final String domains;
        private final int count;
        private final String assessment;
        private final String groupKey;
        private final List<CSPEntry> entries;

        public CSPSummaryRow(String value, String domains, int count, String assessment, String groupKey, List<CSPEntry> entries) {
            this.value = value;
            this.domains = domains;
            this.count = count;
            this.assessment = assessment;
            this.groupKey = groupKey;
            this.entries = entries;
        }

        public String getValue() { return value; }
        public String getDomains() { return domains; }
        public int getCount() { return count; }
        public String getAssessment() { return assessment; }
        public String getGroupKey() { return groupKey; }
        public List<CSPEntry> getEntries() { return entries; }
    }

    private final List<CSPSummaryRow> rows = new ArrayList<>();

    public synchronized void updateData(Map<String, List<CSPEntry>> groupedData) {
        rows.clear();
        if (groupedData != null) {
            List<Map.Entry<String, List<CSPEntry>>> sorted = new ArrayList<>(groupedData.entrySet());
            sorted.sort((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()));

            for (Map.Entry<String, List<CSPEntry>> e : sorted) {
                String groupKey = e.getKey();
                List<CSPEntry> list = e.getValue();
                int count = list.size();

                Set<String> domainSet = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
                for (CSPEntry entry : list) {
                    if (entry.host() != null && !entry.host().isBlank()) {
                        domainSet.add(entry.host());
                    }
                }
                String domains = String.join(", ", domainSet);

                String rawVal;
                if (list.isEmpty()) {
                    rawVal = groupKey;
                } else {
                    CSPEntry first = list.get(0);
                    rawVal = first.isMissingCsp() ? "(missing CSP)" : first.getPrimaryCsp();
                }

                String assessment = evaluateSecurityAssessment(rawVal, list);
                rows.add(new CSPSummaryRow(rawVal, domains, count, assessment, groupKey, list));
            }
        }
        fireTableDataChanged();
    }

    public synchronized String getSummaryValueAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return rows.get(rowIndex).getGroupKey();
        }
        return null;
    }

    public synchronized List<CSPEntry> getEntriesAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return new ArrayList<>(rows.get(rowIndex).getEntries());
        }
        return Collections.emptyList();
    }

    @Override
    public synchronized int getRowCount() {
        return rows.size();
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
            case 0 -> String.class;
            case 1 -> String.class;
            case 2 -> Integer.class;
            case 3 -> String.class;
            default -> Object.class;
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= rows.size()) {
            return null;
        }

        CSPSummaryRow row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.getValue();
            case 1 -> row.getDomains();
            case 2 -> row.getCount();
            case 3 -> row.getAssessment();
            default -> null;
        };
    }

    private String evaluateSecurityAssessment(String pattern, List<CSPEntry> entries) {
        if (pattern == null || pattern.equalsIgnoreCase("(missing CSP)")) {
            return "HIGH: Missing CSP allows unrestricted script execution & Clickjacking";
        }
        if (pattern.equalsIgnoreCase("(not set)")) {
            return "INFO: Directive not explicitly declared";
        }

        List<CspFinding> findings = GoogleCspEvaluator.evaluate(pattern);
        if (findings.isEmpty()) {
            if (pattern.contains("frame-ancestors 'none'") || pattern.contains("frame-ancestors 'self'")) {
                return "GOOD: Restricts framing (Clickjacking defense)";
            }
            return "PASS: Adheres to Google CSP baseline rules";
        }

        CspFinding topFinding = findings.get(0);
        String label = topFinding.severity().getLabel();
        String detail = topFinding.description();
        if (detail.length() > 75) {
            detail = detail.substring(0, 72) + "...";
        }
        return label + ": " + detail;
    }
}
