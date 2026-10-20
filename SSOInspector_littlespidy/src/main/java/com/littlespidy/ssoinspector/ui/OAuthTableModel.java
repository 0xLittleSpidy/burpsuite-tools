// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.ui;

import com.littlespidy.ssoinspector.model.OAuthRequestEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class OAuthTableModel extends AbstractTableModel {

    public static final int COL_ID = 0;
    public static final int COL_TIME = 1;
    public static final int COL_METHOD = 2;
    public static final int COL_HOST = 3;
    public static final int COL_PATH = 4;
    public static final int COL_FLOW = 5;
    public static final int COL_SEVERITY = 6;
    public static final int COL_ISSUES_COUNT = 7;
    public static final int COL_ISSUE_SUMMARY = 8;

    private static final String[] COLUMN_NAMES = {
            "#",
            "Time",
            "Method",
            "Host",
            "Path",
            "Flow Type",
            "Severity",
            "Issues",
            "Issue Summary"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            Integer.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            Integer.class,
            String.class
    };

    private List<OAuthRequestEntry> displayedEntries;

    public OAuthTableModel() {
        this.displayedEntries = new ArrayList<>();
    }

    public synchronized void setEntries(List<OAuthRequestEntry> entries) {
        this.displayedEntries = entries != null ? new ArrayList<>(entries) : new ArrayList<>();
        fireTableDataChanged();
    }

    public synchronized OAuthRequestEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayedEntries.size()) {
            return displayedEntries.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return displayedEntries.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMN_NAMES[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_CLASSES[columnIndex];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        OAuthRequestEntry entry = getEntryAt(rowIndex);
        if (entry == null) return null;

        return switch (columnIndex) {
            case COL_ID -> entry.getId();
            case COL_TIME -> entry.getTimestamp();
            case COL_METHOD -> entry.getMethod();
            case COL_HOST -> entry.getHost();
            case COL_PATH -> entry.getPath();
            case COL_FLOW -> entry.getFlowType().getDisplayName();
            case COL_SEVERITY -> entry.getHighestSeverity().getLabel();
            case COL_ISSUES_COUNT -> entry.getIssuesCount();
            case COL_ISSUE_SUMMARY -> entry.getIssueSummary();
            default -> null;
        };
    }
}
