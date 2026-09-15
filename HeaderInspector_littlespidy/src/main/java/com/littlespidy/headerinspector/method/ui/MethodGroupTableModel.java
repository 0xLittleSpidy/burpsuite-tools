// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.ui;

import com.littlespidy.headerinspector.method.model.MethodGroup;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Master table model displaying grouped HTTP methods along with safe/idempotent/cacheable
 * attributes and request counts.
 *
 * @author littlespidy
 */
public class MethodGroupTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Method",
        "Safe",
        "Idempotent",
        "Cacheable",
        "Total Requests",
        "Domains",
        "Unique Endpoints"
    };

    private final List<MethodGroup> groups = new ArrayList<>();

    public void setGroups(List<MethodGroup> newGroups) {
        this.groups.clear();
        if (newGroups != null) {
            this.groups.addAll(newGroups);
        }
        fireTableDataChanged();
    }

    public MethodGroup getGroupAt(int rowIndex) {
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
            case 0, 1, 2, 3 -> String.class;
            case 4, 5, 6 -> Integer.class;
            default -> Object.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        MethodGroup g = groups.get(rowIndex);
        if (g == null) return "";
        return switch (columnIndex) {
            case 0 -> g.method();
            case 1 -> g.safeFormatted();
            case 2 -> g.idempotentFormatted();
            case 3 -> g.cacheable();
            case 4 -> g.totalRequests();
            case 5 -> g.uniqueDomainsCount();
            case 6 -> g.uniqueEndpointsCount();
            default -> "";
        };
    }
}
