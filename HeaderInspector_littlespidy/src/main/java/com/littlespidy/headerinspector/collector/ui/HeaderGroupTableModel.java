// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.ui;

import com.littlespidy.headerinspector.collector.knowledge.HttpDevKnowledgeBase;
import com.littlespidy.headerinspector.collector.model.HeaderNameGroup;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Master table model displaying grouped HTTP headers with summary statistics
 * and category from http.dev knowledge base.
 *
 * @author littlespidy
 */
public class HeaderGroupTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Type",
        "Header Name",
        "Category",
        "Unique Values",
        "Domains",
        "Total Count"
    };

    private final List<HeaderNameGroup> groups = new ArrayList<>();

    public void setGroups(List<HeaderNameGroup> newGroups) {
        this.groups.clear();
        if (newGroups != null) {
            this.groups.addAll(newGroups);
        }
        fireTableDataChanged();
    }

    public HeaderNameGroup getGroupAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < groups.size()) {
            return groups.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return groups.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMNS[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case 0, 1, 2 -> String.class;
            case 3, 4, 5 -> Integer.class;
            default -> Object.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        HeaderNameGroup g = groups.get(rowIndex);
        if (g == null) return "";
        return switch (columnIndex) {
            case 0 -> g.type().display();
            case 1 -> g.displayName();
            case 2 -> HttpDevKnowledgeBase.getCategory(g.headerName());
            case 3 -> g.uniqueValuesCount();
            case 4 -> g.domainsCount();
            case 5 -> g.totalOccurrences();
            default -> "";
        };
    }
}
