// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.cache.ui;

import com.littlespidy.headerinspector.cache.model.CacheEntry;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Table model displaying grouped cache directive values per domain, occurrence counts,
 * and security assessments. Every value has its own separate row, URL count, and assessment.
 *
 * @author littlespidy
 */
public class CacheSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Domain Name",
        "Value",
        "URL Count",
        "Assessment"
    };

    public static class CacheSummaryRow {
        private final String domain;
        private final String value;
        private final int count;
        private final String assessment;
        private final List<CacheEntry> entries;

        public CacheSummaryRow(String domain, String value, int count, String assessment, List<CacheEntry> entries) {
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
        public List<CacheEntry> getEntries() { return entries; }
    }

    private final List<CacheSummaryRow> rows = new ArrayList<>();

    public synchronized void updateData(String headerName, List<CacheEntry> entries) {
        rows.clear();
        if (entries == null || entries.isEmpty()) {
            fireTableDataChanged();
            return;
        }

        Map<String, List<CacheEntry>> map = new LinkedHashMap<>();
        for (CacheEntry entry : entries) {
            String domain = (entry.host() != null && !entry.host().isBlank()) ? entry.host().trim() : "(unknown)";
            String val = entry.getHeaderValue(headerName);
            if (val == null || val.isBlank()) val = "(not set)";
            String key = domain.toLowerCase() + "\t" + val;
            map.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
        }

        for (Map.Entry<String, List<CacheEntry>> e : map.entrySet()) {
            List<CacheEntry> list = e.getValue();
            CacheEntry first = list.get(0);
            String domain = (first.host() != null && !first.host().isBlank()) ? first.host().trim() : "(unknown)";
            String val = e.getKey().substring(e.getKey().indexOf('\t') + 1);
            int count = list.size();
            String assessment = evaluateSecurityAssessment(headerName, val);
            rows.add(new CacheSummaryRow(domain, val, count, assessment, list));
        }

        rows.sort(Comparator.comparing((CacheSummaryRow r) -> r.getDomain().toLowerCase())
                .thenComparing(CacheSummaryRow::getValue));
        fireTableDataChanged();
    }

    public synchronized CacheSummaryRow getRowAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return rows.get(rowIndex);
        }
        return null;
    }

    public synchronized List<CacheEntry> getEntriesAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return new ArrayList<>(rows.get(rowIndex).getEntries());
        }
        return Collections.emptyList();
    }

    public synchronized int getTotalUrlCount() {
        int total = 0;
        for (CacheSummaryRow row : rows) {
            total += row.getCount();
        }
        return total;
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

        CacheSummaryRow row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.getDomain();
            case 1 -> row.getValue();
            case 2 -> row.getCount();
            case 3 -> row.getAssessment();
            default -> null;
        };
    }

    public static String evaluateSecurityAssessment(String headerName, String value) {
        String h = headerName != null ? headerName.trim() : "";
        String v = value != null ? value.trim() : "";
        String vLower = v.toLowerCase();

        if (h.equalsIgnoreCase("Cache-Control") || h.equalsIgnoreCase("CDN-Cache-Control") || h.equalsIgnoreCase("Surrogate-Control")) {
            if (v.isBlank() || v.equalsIgnoreCase("(not set)") || v.equalsIgnoreCase("(missing)")) {
                return "MEDIUM: Missing Cache-Control directive allows heuristic proxy and browser caching";
            }
            if (vLower.contains("no-store")) {
                return "GOOD: 'no-store' prevents all intermediate and browser storage (secure for sensitive data)";
            }
            if (vLower.contains("no-cache")) {
                return "LOW: 'no-cache' requires revalidation before reuse (does not prevent client storage)";
            }
            if (vLower.contains("private")) {
                return "GOOD: 'private' restricts caching to the client browser (prevents shared CDN storage)";
            }
            if (vLower.contains("public")) {
                if (vLower.contains("max-age=0") || vLower.contains("s-maxage=0")) {
                    return "LOW: 'public' response declared with zero max-age";
                }
                return "INFO: 'public' explicitly permits caching by shared proxies and CDNs";
            }
            if (vLower.contains("max-age")) {
                return "INFO: Standard max-age caching duration";
            }
            return "INFO: Custom or vendor caching directive";
        }

        if (h.equalsIgnoreCase("Pragma")) {
            if (vLower.contains("no-cache")) {
                return "LOW: Legacy HTTP/1.0 directive 'no-cache' (use Cache-Control: no-store instead)";
            }
            if (v.equalsIgnoreCase("(not set)")) {
                return "INFO: Pragma not set (modern HTTP/1.1 uses Cache-Control)";
            }
            return "INFO: Legacy Pragma directive";
        }

        if (h.equalsIgnoreCase("Expires")) {
            if (v.equalsIgnoreCase("(not set)")) {
                return "INFO: Expires header not set";
            }
            if (v.equals("0") || v.equals("-1")) {
                return "GOOD: Immediate expiration declared";
            }
            return "INFO: Absolute expiration timestamp specified";
        }

        if (h.equalsIgnoreCase("ETag")) {
            if (v.equalsIgnoreCase("(not set)")) {
                return "INFO: ETag validator not present";
            }
            return "GOOD: Entity tag present for conditional validation (304 Not Modified)";
        }

        if (h.equalsIgnoreCase("Last-Modified")) {
            if (v.equalsIgnoreCase("(not set)")) {
                return "INFO: Last-Modified timestamp not present";
            }
            return "GOOD: Last-Modified timestamp present for conditional validation";
        }

        if (h.equalsIgnoreCase("Vary")) {
            if (v.equalsIgnoreCase("(not set)")) {
                return "INFO: Vary header not present";
            }
            if (vLower.contains("cookie") || vLower.contains("authorization")) {
                return "GOOD: Keyed by user credentials to prevent cross-user cache poison/leak";
            }
            return "INFO: Cache keyed by specified request headers";
        }

        if (v.equalsIgnoreCase("(not set)")) {
            return "INFO: Header not present";
        }
        return "INFO: Caching metadata / diagnostic header";
    }
}
