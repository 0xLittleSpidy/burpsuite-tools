package com.littlespidy.parampayloadinjector.ui;

import com.littlespidy.parampayloadinjector.model.ReflectionFinding;
import burp.api.montoya.MontoyaApi;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Table model for displaying detected reflections with live search and scope filtering.
 */
public class ReflectionTableModel extends AbstractTableModel {

    private final MontoyaApi api;
    private final List<ReflectionFinding> allFindings = Collections.synchronizedList(new ArrayList<>());
    private final List<ReflectionFinding> filteredFindings = new ArrayList<>();

    private boolean inScopeOnly = false;
    private String searchText = "";
    private String categoryFilter = "All";

    private final String[] columns = {
            "#", "Time", "Method", "URL", "Status", "Parameter", "Category", "Context", "Payload", "Evidence"
    };

    public ReflectionTableModel(MontoyaApi api) {
        this.api = api;
    }

    public synchronized void addFinding(ReflectionFinding finding) {
        allFindings.add(finding);
        applyFilter();
    }

    public synchronized void clear() {
        allFindings.clear();
        filteredFindings.clear();
        fireTableDataChanged();
    }

    public synchronized void setInScopeOnly(boolean inScopeOnly) {
        this.inScopeOnly = inScopeOnly;
        applyFilter();
    }

    public synchronized void setSearchText(String searchText) {
        this.searchText = (searchText == null) ? "" : searchText.trim().toLowerCase();
        applyFilter();
    }

    public synchronized void setCategoryFilter(String categoryFilter) {
        this.categoryFilter = (categoryFilter == null) ? "All" : categoryFilter;
        applyFilter();
    }

    public synchronized void applyFilter() {
        filteredFindings.clear();
        for (ReflectionFinding f : allFindings) {
            if (inScopeOnly && api != null && !api.scope().isInScope(f.getUrl())) {
                continue;
            }

            if (!categoryFilter.equalsIgnoreCase("All") && !f.getPayloadCategory().equalsIgnoreCase(categoryFilter)) {
                continue;
            }

            if (!searchText.isEmpty()) {
                String target = (f.getUrl() + " " + f.getParameterName() + " " + f.getInjectedPayload() + " " + f.getEvidenceSnippet()).toLowerCase();
                if (!target.contains(searchText)) {
                    continue;
                }
            }

            filteredFindings.add(f);
        }
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return filteredFindings.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int column) {
        return columns[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= filteredFindings.size()) return null;
        ReflectionFinding f = filteredFindings.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> f.getId();
            case 1 -> f.getTimestamp();
            case 2 -> f.getMethod();
            case 3 -> f.getUrl();
            case 4 -> f.getStatusCode();
            case 5 -> f.getParameterName();
            case 6 -> f.getPayloadCategory();
            case 7 -> f.getReflectionContext();
            case 8 -> f.getInjectedPayload();
            case 9 -> f.getEvidenceSnippet();
            default -> null;
        };
    }

    public ReflectionFinding getFindingAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < filteredFindings.size()) {
            return filteredFindings.get(rowIndex);
        }
        return null;
    }

    public int getTotalCount() {
        return allFindings.size();
    }

    public int getFilteredCount() {
        return filteredFindings.size();
    }
}
