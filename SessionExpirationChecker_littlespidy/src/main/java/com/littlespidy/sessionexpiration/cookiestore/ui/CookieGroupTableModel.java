// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.ui;

import com.littlespidy.sessionexpiration.cookiestore.model.CookieNameGroup;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model displaying grouped cookie names, unique value counts, total occurrences,
 * and associated domains.
 *
 * @author littlespidy
 */
public class CookieGroupTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "#", "Cookie Name", "Source", "Unique Values", "Total Seen", "Domains"
    };

    private List<CookieNameGroup> displayedGroups = new ArrayList<>();

    public void setGroups(List<CookieNameGroup> groups) {
        this.displayedGroups = (groups != null) ? new ArrayList<>(groups) : new ArrayList<>();
        fireTableDataChanged();
    }

    public CookieNameGroup getGroupAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayedGroups.size()) {
            return displayedGroups.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return displayedGroups.size();
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
        switch (columnIndex) {
            case 0:
            case 3:
            case 4:
            case 5:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        CookieNameGroup group = getGroupAt(rowIndex);
        if (group == null) return null;

        switch (columnIndex) {
            case 0: return rowIndex + 1;
            case 1: return group.displayName();
            case 2: return group.source().getDisplayName();
            case 3: return group.uniqueValuesCount();
            case 4: return group.totalOccurrences();
            case 5: return group.domainsCount();
            default: return "";
        }
    }
}
