// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import com.littlespidy.gwtmap.model.GWTService;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying enumerated GWT RPC services and policy hashes.
 *
 * @author littlespidy
 */
public class GWTServiceTableModel extends AbstractTableModel {

    private final String[] columnNames = {
            "Service Endpoint Path", "Serialization Policy Strong Name", "Discovered Methods"
    };

    private final List<GWTService> services = new ArrayList<>();

    public void setServices(List<GWTService> newServices) {
        services.clear();
        if (newServices != null) {
            services.addAll(newServices);
        }
        fireTableDataChanged();
    }

    public GWTService getServiceAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < services.size()) {
            return services.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return services.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 2) return Integer.class;
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        GWTService s = services.get(rowIndex);
        switch (columnIndex) {
            case 0: return s.getServicePath();
            case 1: return s.getStrongName();
            case 2: return s.getMethodCount();
            default: return "";
        }
    }
}
