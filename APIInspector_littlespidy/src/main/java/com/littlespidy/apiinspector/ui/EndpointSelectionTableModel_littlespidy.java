// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Table model for selecting endpoints from imported collections for security attacks.
 */
public class EndpointSelectionTableModel_littlespidy extends AbstractTableModel {

    private final String[] columns = {"Sel", "Method", "Path", "Summary", "Auth"};
    private final List<EndpointSelectionItem_littlespidy> allItems = new ArrayList<>();
    private final List<EndpointSelectionItem_littlespidy> displayedItems = new ArrayList<>();
    private String currentFilter = "";

    public void setItems(List<? extends EndpointSelectionItem_littlespidy> list) {
        allItems.clear();
        if (list != null) {
            allItems.addAll(list);
        }
        applyFilter(currentFilter);
    }

    public List<EndpointSelectionItem_littlespidy> getAllItems() {
        return allItems;
    }

    public List<EndpointSelectionItem_littlespidy> getDisplayedItems() {
        return displayedItems;
    }

    public List<EndpointSelectionItem_littlespidy> getSelectedItems() {
        List<EndpointSelectionItem_littlespidy> sel = new ArrayList<>();
        for (EndpointSelectionItem_littlespidy it : allItems) {
            if (it.selected) {
                sel.add(it);
            }
        }
        return sel;
    }

    public void selectAll(boolean select) {
        for (EndpointSelectionItem_littlespidy it : displayedItems) {
            it.selected = select;
        }
        fireTableDataChanged();
    }

    public void applyFilter(String query) {
        this.currentFilter = query != null ? query.trim().toLowerCase(Locale.ROOT) : "";
        displayedItems.clear();

        if (currentFilter.isEmpty()) {
            displayedItems.addAll(allItems);
        } else {
            for (EndpointSelectionItem_littlespidy it : allItems) {
                DiscoveredEndpoint_littlespidy ep = it.getEndpoint();
                String m = ep.getMethod() != null ? ep.getMethod().toLowerCase(Locale.ROOT) : "";
                String p = ep.getPath() != null ? ep.getPath().toLowerCase(Locale.ROOT) : "";
                String s = ep.getSummary() != null ? ep.getSummary().toLowerCase(Locale.ROOT) : "";

                if (m.contains(currentFilter) || p.contains(currentFilter) || s.contains(currentFilter)) {
                    displayedItems.add(it);
                }
            }
        }
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return displayedItems.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int col) {
        return columns[col];
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return col == 0 ? Boolean.class : String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 0;
    }

    @Override
    public void setValueAt(Object aValue, int row, int col) {
        if (col == 0 && aValue instanceof Boolean && row >= 0 && row < displayedItems.size()) {
            displayedItems.get(row).selected = (Boolean) aValue;
            fireTableCellUpdated(row, col);
        }
    }

    @Override
    public Object getValueAt(int row, int col) {
        if (row < 0 || row >= displayedItems.size()) {
            return "";
        }
        EndpointSelectionItem_littlespidy it = displayedItems.get(row);
        DiscoveredEndpoint_littlespidy ep = it.getEndpoint();
        switch (col) {
            case 0:
                return it.selected;
            case 1:
                return ep.getMethod();
            case 2:
                return ep.getPath();
            case 3:
                return ep.getSummary() != null && !ep.getSummary().isBlank() ? ep.getSummary() : "-";
            case 4:
                return ep.isRequiresAuth() ? "Required" : "None";
            default:
                return "";
        }
    }
}
