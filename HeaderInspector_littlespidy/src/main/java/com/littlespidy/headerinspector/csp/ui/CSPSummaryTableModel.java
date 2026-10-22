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
 * Summary table model showing unique CSP values per domain, occurrence counts, and security assessments.
 * Every value has its own row, URL count, and assessment.
 *
 * @author littlespidy
 */
public class CSPSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Domain Name",
        "Value",
        "URL Count",
        "Assessment"
    };

    public static class CSPSummaryRow {
        private final String domain;
        private final String value;
        private final int count;
        private final String assessment;
        private final List<CSPEntry> entries;

        public CSPSummaryRow(String domain, String value, int count, String assessment, List<CSPEntry> entries) {
            this.domain = domain;
            this.value = value;
            this.count = count;
            this.assessment = assessment;
            this.entries = entries;
        }

        public String getDomain() { return domain; }
        public String getValue() { return value; }
        public int getCount() { return count; }
        public String getAssessment() { return assessment; }
        public List<CSPEntry> getEntries() { return entries; }
    }

    private final List<CSPSummaryRow> rows = new ArrayList<>();

    public synchronized void updateData(List<CSPEntry> entries, String mode) {
        rows.clear();
        if (entries == null || entries.isEmpty()) {
            fireTableDataChanged();
            return;
        }

        String normalizedMode = mode != null ? mode.trim() : "Full Policy";
        Map<String, List<CSPEntry>> map = new LinkedHashMap<>();

        for (CSPEntry entry : entries) {
            String domain = (entry.host() != null && !entry.host().isBlank()) ? entry.host().trim() : "(unknown)";
            if (normalizedMode.equalsIgnoreCase("All Sources (Directives)")) {
                if (entry.isMissingCsp()) {
                    String key = domain.toLowerCase() + "\t(missing CSP)";
                    map.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
                } else {
                    Set<String> seenTokens = new HashSet<>();
                    for (Map.Entry<String, List<String>> dir : entry.parsedDirectives().entrySet()) {
                        String directiveName = dir.getKey();
                        for (String token : dir.getValue()) {
                            String itemKey = directiveName + " " + token;
                            if (seenTokens.add(itemKey)) {
                                String key = domain.toLowerCase() + "\t" + itemKey;
                                map.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
                            }
                        }
                    }
                }
            } else {
                String val = deriveValue(entry, normalizedMode);
                String key = domain.toLowerCase() + "\t" + val;
                map.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
            }
        }

        for (Map.Entry<String, List<CSPEntry>> e : map.entrySet()) {
            List<CSPEntry> list = e.getValue();
            CSPEntry first = list.get(0);
            String domain = (first.host() != null && !first.host().isBlank()) ? first.host().trim() : "(unknown)";
            String val = e.getKey().substring(e.getKey().indexOf('\t') + 1);
            int count = list.size();
            String assessment = evaluateSecurityAssessment(val, list);
            rows.add(new CSPSummaryRow(domain, val, count, assessment, list));
        }

        rows.sort(Comparator.comparing((CSPSummaryRow r) -> r.getDomain().toLowerCase())
                .thenComparing(CSPSummaryRow::getValue));
        fireTableDataChanged();
    }

    private static String deriveValue(CSPEntry entry, String mode) {
        if (mode.equalsIgnoreCase("Full Policy")) {
            return entry.isMissingCsp() ? "(missing CSP)" : entry.getPrimaryCsp();
        } else if (mode.equalsIgnoreCase("CSP-Report-Only")) {
            return (entry.cspReportOnlyHeader() != null && !entry.cspReportOnlyHeader().trim().isEmpty())
                    ? entry.cspReportOnlyHeader().trim()
                    : "(not set)";
        } else {
            return entry.getDirectiveString(mode);
        }
    }

    public synchronized CSPSummaryRow getRowAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return rows.get(rowIndex);
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
            case 0 -> row.getDomain();
            case 1 -> row.getValue();
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
