// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.ui;

import com.littlespidy.headerinspector.status.model.StatusGroup;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Master table model displaying grouped HTTP status codes along with reason phrase,
 * class, meaning, and response counts.
 *
 * @author littlespidy
 */
public class StatusGroupTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Status Code",
        "Reason / Name",
        "Class",
        "Meaning",
        "Total Responses",
        "Domains",
        "Unique Endpoints"
    };

    private final List<StatusGroup> groups = new ArrayList<>();

    public void setGroups(List<StatusGroup> newGroups) {
        this.groups.clear();
        if (newGroups != null) {
            this.groups.addAll(newGroups);
        }
        fireTableDataChanged();
    }

    public StatusGroup getGroupAt(int rowIndex) {
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
            case 0, 4, 5, 6 -> Integer.class;
            case 1, 2, 3 -> String.class;
            default -> Object.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        StatusGroup g = groups.get(rowIndex);
        if (g == null) return "";
        return switch (columnIndex) {
            case 0 -> g.statusCode();
            case 1 -> g.reasonPhrase();
            case 2 -> g.statusClass();
            case 3 -> g.meaning();
            case 4 -> g.totalResponses();
            case 5 -> g.uniqueDomainsCount();
            case 6 -> g.uniqueEndpointsCount();
            default -> "";
        };
    }
}
