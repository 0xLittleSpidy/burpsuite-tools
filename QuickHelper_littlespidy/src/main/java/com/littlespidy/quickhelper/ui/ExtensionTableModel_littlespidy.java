// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import com.littlespidy.quickhelper.model.ExtensionItem_littlespidy;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model displaying the catalog of downloadable Burp Suite extensions.
 */
public class ExtensionTableModel_littlespidy extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "Select",
            "Extension Name",
            "Category",
            "JAR File Name",
            "Est. Size",
            "Download Status"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            Boolean.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class
    };

    private final List<ExtensionItem_littlespidy> allItems;
    private final List<ExtensionItem_littlespidy> filteredItems;
    private String currentFilter = "";

    public ExtensionTableModel_littlespidy(List<ExtensionItem_littlespidy> items) {
        this.allItems = new ArrayList<>(items);
        this.filteredItems = new ArrayList<>(items);
    }

    @Override
    public int getRowCount() {
        return filteredItems.size();
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
        return COLUMN_CLASSES[columnIndex];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= filteredItems.size()) {
            return null;
        }

        ExtensionItem_littlespidy item = filteredItems.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return item.isSelected();
            case 1:
                return item.getName();
            case 2:
                return item.getCategory();
            case 3:
                return item.getJarFileName();
            case 4:
                return item.getEstimatedSize();
            case 5:
                return item.getStatusMessage();
            default:
                return "";
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= filteredItems.size()) {
            return;
        }

        if (columnIndex == 0 && aValue instanceof Boolean) {
            ExtensionItem_littlespidy item = filteredItems.get(rowIndex);
            item.setSelected((Boolean) aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }

    public ExtensionItem_littlespidy getItemAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < filteredItems.size()) {
            return filteredItems.get(rowIndex);
        }
        return null;
    }

    public List<ExtensionItem_littlespidy> getAllItems() {
        return allItems;
    }

    public List<ExtensionItem_littlespidy> getFilteredItems() {
        return filteredItems;
    }

    public void selectAll(boolean select) {
        for (ExtensionItem_littlespidy item : filteredItems) {
            item.setSelected(select);
        }
        fireTableDataChanged();
    }

    public void setFilter(String filterText) {
        this.currentFilter = (filterText == null) ? "" : filterText.trim().toLowerCase();
        applyFilter();
    }

    private void applyFilter() {
        filteredItems.clear();
        if (currentFilter.isEmpty()) {
            filteredItems.addAll(allItems);
        } else {
            for (ExtensionItem_littlespidy item : allItems) {
                if (item.getName().toLowerCase().contains(currentFilter)
                        || item.getCategory().toLowerCase().contains(currentFilter)
                        || item.getJarFileName().toLowerCase().contains(currentFilter)
                        || item.getDescription().toLowerCase().contains(currentFilter)) {
                    filteredItems.add(item);
                }
            }
        }
        fireTableDataChanged();
    }

    public void itemUpdated(ExtensionItem_littlespidy item) {
        int index = filteredItems.indexOf(item);
        if (index >= 0) {
            fireTableRowsUpdated(index, index);
        }
    }
}
