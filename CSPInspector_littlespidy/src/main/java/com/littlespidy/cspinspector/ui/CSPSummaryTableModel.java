// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.ui;

import com.littlespidy.cspinspector.model.CSPEntry;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Summary table model showing unique CSP values/patterns, counts, and security assessments.
 *
 * @author littlespidy
 */
public class CSPSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "CSP Directive / Policy Value",
        "URL Count",
        "Security Assessment"
    };

    private final List<Map.Entry<String, List<CSPEntry>>> rows = new ArrayList<>();

    public synchronized void updateData(Map<String, List<CSPEntry>> groupedData) {
        rows.clear();
        if (groupedData != null) {
            List<Map.Entry<String, List<CSPEntry>>> sorted = new ArrayList<>(groupedData.entrySet());
            sorted.sort((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()));
            rows.addAll(sorted);
        }
        fireTableDataChanged();
    }

    public synchronized String getSummaryValueAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return rows.get(rowIndex).getKey();
        }
        return null;
    }

    public synchronized List<CSPEntry> getEntriesAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rows.size()) {
            return new ArrayList<>(rows.get(rowIndex).getValue());
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
            case 1 -> Integer.class;
            case 2 -> String.class;
            default -> Object.class;
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= rows.size()) {
            return null;
        }

        Map.Entry<String, List<CSPEntry>> row = rows.get(rowIndex);
        String val = row.getKey();
        List<CSPEntry> list = row.getValue();

        return switch (columnIndex) {
            case 0 -> val;
            case 1 -> list.size();
            case 2 -> evaluateSecurityAssessment(val, list);
            default -> null;
        };
    }

    private String evaluateSecurityAssessment(String pattern, List<CSPEntry> entries) {
        if (pattern.equalsIgnoreCase("(missing CSP)")) {
            return "CRITICAL: Missing CSP allows unrestricted script execution & Clickjacking";
        }
        if (pattern.contains("'unsafe-inline'")) {
            return "HIGH: 'unsafe-inline' bypasses XSS protection";
        }
        if (pattern.contains("'unsafe-eval'")) {
            return "MEDIUM: 'unsafe-eval' allows dynamic string execution";
        }
        if (pattern.contains("data:") || pattern.contains("blob:")) {
            return "MEDIUM: data:/blob: URI sources may facilitate injection";
        }
        if (pattern.contains("*") || pattern.contains("https://*") || pattern.contains("http://*")) {
            return "MEDIUM: Wildcard host allows loading scripts from any domain";
        }
        if (pattern.contains("frame-ancestors 'none'") || pattern.contains("frame-ancestors 'self'")) {
            return "GOOD: Restricts framing (Clickjacking defense)";
        }
        if (pattern.equalsIgnoreCase("(not set)")) {
            return "INFO: Directive not explicitly declared";
        }
        return "STANDARD";
    }
}
