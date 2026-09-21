// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiefinder;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying systematic session cookie and header test results.
 *
 * @author littlespidy
 */
public class CookieFinderTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "#",
            "Component Tested",
            "Type",
            "Value Preview",
            "HTTP Status",
            "Length",
            "Delta",
            "Verdict",
            "Analysis & Details",
            "Time"
    };

    private final List<FinderResult> entries = new ArrayList<>();

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> Integer.class;
            case 4, 5, 6 -> Long.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) return null;
        FinderResult r = entries.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> r.getId();
            case 1 -> r.getComponentName();
            case 2 -> formatType(r.getType());
            case 3 -> r.getRawValuePreview();
            case 4 -> r.getStatusCode() > 0 ? (long) r.getStatusCode() : "-";
            case 5 -> r.getResponseLength() > 0 ? r.getResponseLength() : "-";
            case 6 -> (r.getLengthDelta() > 0 ? "+" : "") + r.getLengthDelta() + " B";
            case 7 -> r.getVerdict();
            case 8 -> r.getSignalDetails();
            case 9 -> r.getDurationMs() + " ms";
            default -> "";
        };
    }

    private String formatType(FinderResult.TestType type) {
        if (type == null) return "";
        return switch (type) {
            case BASELINE -> "🎯 Baseline";
            case ANONYMOUS -> "🔒 Anonymous";
            case COOKIE -> "🍪 Cookie";
            case AUTH_HEADER -> "🔑 Standard Auth";
            case CUSTOM_HEADER -> "⚙️ Custom Header";
            case GROUP_ALL_COOKIES -> "📦 Group (No Cookies)";
            case GROUP_ALL_HEADERS -> "📦 Group (No Auth Headers)";
        };
    }

    public void addResult(FinderResult result) {
        entries.add(result);
        int idx = entries.size() - 1;
        fireTableRowsInserted(idx, idx);
    }

    public void setResults(List<FinderResult> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public void clear() {
        entries.clear();
        fireTableDataChanged();
    }

    public FinderResult getResultAt(int row) {
        if (row >= 0 && row < entries.size()) {
            return entries.get(row);
        }
        return null;
    }

    public List<FinderResult> getAllResults() {
        return new ArrayList<>(entries);
    }
}
