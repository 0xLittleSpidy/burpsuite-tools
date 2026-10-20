// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.ui;

import com.littlespidy.ssoinspector.model.SSOAuditIssue;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class AuditIssueTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "Severity",
            "Confidence",
            "Issue Title",
            "Audit Type"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            String.class,
            String.class,
            String.class,
            String.class
    };

    private List<SSOAuditIssue> issues;

    public AuditIssueTableModel() {
        this.issues = new ArrayList<>();
    }

    public synchronized void setIssues(List<SSOAuditIssue> issues) {
        this.issues = issues != null ? new ArrayList<>(issues) : new ArrayList<>();
        fireTableDataChanged();
    }

    public synchronized SSOAuditIssue getIssueAt(int row) {
        if (row >= 0 && row < issues.size()) {
            return issues.get(row);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return issues.size();
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
        SSOAuditIssue issue = getIssueAt(rowIndex);
        if (issue == null) return null;

        return switch (columnIndex) {
            case 0 -> issue.getSeverity().getLabel();
            case 1 -> issue.getConfidence().getLabel();
            case 2 -> issue.getTitle();
            case 3 -> issue.isActiveProbe() ? "Active Probe" : "Passive Audit";
            default -> null;
        };
    }
}
