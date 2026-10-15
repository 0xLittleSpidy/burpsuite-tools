// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.ui;

import com.littlespidy.jwtcomparator.attacker.model.AttackedRequestEntry;
import com.littlespidy.jwtcomparator.attacker.model.TokenAttackResult;
import com.littlespidy.jwtcomparator.model.JWTTokenModel;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Dynamic TableModel for the Token Attacker access matrix.
 * Adapts columns dynamically based on active token slots and unauthenticated testing toggle.
 */
public class TokenAttackTableModel extends AbstractTableModel {

    private final List<AttackedRequestEntry> allEntries = new ArrayList<>();
    private final List<AttackedRequestEntry> displayEntries = new ArrayList<>();
    private final List<JWTTokenModel> activeTokens = new ArrayList<>();
    private boolean testUnauth = true;

    private String searchFilter = "";
    private String viewFilter = "All Requests";

    public synchronized void updateSchema(List<JWTTokenModel> tokens, boolean testUnauth) {
        this.activeTokens.clear();
        if (tokens != null) {
            for (JWTTokenModel tm : tokens) {
                if (tm.getRawToken() != null && !tm.getRawToken().trim().isEmpty()) {
                    this.activeTokens.add(tm);
                }
            }
        }
        this.testUnauth = testUnauth;
        fireTableStructureChanged();
    }

    public synchronized void setRequests(List<AttackedRequestEntry> entries) {
        allEntries.clear();
        if (entries != null) {
            allEntries.addAll(entries);
        }
        applyFilter();
    }

    public synchronized void addRequests(List<AttackedRequestEntry> entries) {
        if (entries != null) {
            allEntries.addAll(entries);
        }
        applyFilter();
    }

    public synchronized void addRequest(AttackedRequestEntry entry) {
        if (entry != null) {
            allEntries.add(entry);
        }
        applyFilter();
    }

    public synchronized void clear() {
        allEntries.clear();
        displayEntries.clear();
        fireTableDataChanged();
    }

    public synchronized void applyFilter(String viewFilter, String searchFilter) {
        this.viewFilter = viewFilter != null ? viewFilter : "All Requests";
        this.searchFilter = searchFilter != null ? searchFilter.trim().toLowerCase() : "";
        applyFilter();
    }

    public synchronized void applyFilter() {
        displayEntries.clear();
        for (AttackedRequestEntry entry : allEntries) {
            if (matchesFilter(entry)) {
                displayEntries.add(entry);
            }
        }
        fireTableDataChanged();
    }

    private boolean matchesFilter(AttackedRequestEntry entry) {
        // Search filter
        if (!searchFilter.isEmpty()) {
            boolean matchesSearch = entry.getUrl().toLowerCase().contains(searchFilter)
                    || entry.getPath().toLowerCase().contains(searchFilter)
                    || entry.getMethod().toLowerCase().contains(searchFilter)
                    || entry.getAssessment().toLowerCase().contains(searchFilter);
            if (!matchesSearch) {
                return false;
            }
        }

        // View filter
        if ("Vulnerabilities / Bypasses Only".equalsIgnoreCase(viewFilter)) {
            String assess = entry.getAssessment();
            return assess.contains("🚨") || assess.contains("⚠️");
        } else if ("Accepted by Multiple Tokens".equalsIgnoreCase(viewFilter)) {
            int accepted = 0;
            for (JWTTokenModel tm : activeTokens) {
                TokenAttackResult r = entry.getTokenResult(tm.getSlotIndex());
                if (r != null && r.isAccepted()) accepted++;
            }
            return accepted > 1;
        } else if ("Unauthenticated Allowed".equalsIgnoreCase(viewFilter)) {
            TokenAttackResult unauth = entry.getUnauthenticatedResult();
            return unauth != null && unauth.isAccepted();
        }

        return true;
    }

    public synchronized AttackedRequestEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayEntries.size()) {
            return displayEntries.get(rowIndex);
        }
        return null;
    }

    public synchronized int getEntryRowIndex(AttackedRequestEntry entry) {
        return displayEntries.indexOf(entry);
    }

    public synchronized List<AttackedRequestEntry> getAllEntries() {
        return new ArrayList<>(allEntries);
    }

    @Override
    public synchronized int getRowCount() {
        return displayEntries.size();
    }

    @Override
    public synchronized int getColumnCount() {
        // 0: #, 1: Method, 2: Endpoint / Path, 3: Baseline (Orig),
        // Active Tokens (N), Unauth (0 or 1), Assessment (1)
        return 4 + activeTokens.size() + (testUnauth ? 1 : 0) + 1;
    }

    @Override
    public synchronized String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "Endpoint / Path";
            case 3:
                return "Baseline (Orig)";
            default:
                int tokenIdx = columnIndex - 4;
                if (tokenIdx >= 0 && tokenIdx < activeTokens.size()) {
                    JWTTokenModel tm = activeTokens.get(tokenIdx);
                    return "T" + tm.getSlotIndex() + " (" + tm.getLabel() + ")";
                }
                if (testUnauth && tokenIdx == activeTokens.size()) {
                    return "Unauth (No Token)";
                }
                return "Assessment";
        }
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= displayEntries.size()) {
            return null;
        }
        AttackedRequestEntry entry = displayEntries.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return entry.getId();
            case 1:
                return entry.getMethod();
            case 2:
                String path = entry.getPath();
                return (path != null && !path.isEmpty()) ? path : entry.getUrl();
            case 3:
                if (entry.getOriginalStatusCode() > 0) {
                    return entry.getOriginalStatusCode() + " (" + formatLength(entry.getOriginalLength()) + ")";
                }
                return "-";
            default:
                int tokenIdx = columnIndex - 4;
                if (tokenIdx >= 0 && tokenIdx < activeTokens.size()) {
                    JWTTokenModel tm = activeTokens.get(tokenIdx);
                    return entry.getTokenResult(tm.getSlotIndex());
                }
                if (testUnauth && tokenIdx == activeTokens.size()) {
                    return entry.getUnauthenticatedResult();
                }
                return entry.getAssessment();
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Integer.class;
        }
        if (columnIndex >= 4 && columnIndex < 4 + activeTokens.size() + (testUnauth ? 1 : 0)) {
            return TokenAttackResult.class;
        }
        return String.class;
    }

    private static String formatLength(int bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        }
    }
}
