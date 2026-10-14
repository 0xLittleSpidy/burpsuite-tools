// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import com.littlespidy.gwtmap.model.GWTMethod;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying discovered GWT RPC methods and probe statuses.
 *
 * @author littlespidy
 */
public class GWTMethodTableModel extends AbstractTableModel {

    private final String[] columnNames = {
            "#", "Service", "Method", "Parameters", "Endpoint URL", "Status", "Time", "Length"
    };

    private final List<GWTMethod> methods = new ArrayList<>();

    public void setMethods(List<GWTMethod> newMethods) {
        methods.clear();
        if (newMethods != null) {
            methods.addAll(newMethods);
        }
        fireTableDataChanged();
    }

    public GWTMethod getMethodAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < methods.size()) {
            return methods.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return methods.size();
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
        switch (columnIndex) {
            case 0: return Integer.class;
            case 6: return String.class;
            case 7: return Integer.class;
            default: return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        GWTMethod m = methods.get(rowIndex);
        switch (columnIndex) {
            case 0: return m.getId();
            case 1: return m.getServiceCategory();
            case 2: return m.getMethodName();
            case 3: return "(" + String.join(", ", m.getMethodSignature()) + ")";
            case 4: return m.getFullEndpointUrl();
            case 5:
                if (!m.isProbed()) return "Not Tested";
                return m.getProbeStatusCode() > 0 ? "HTTP " + m.getProbeStatusCode() : "Failed";
            case 6: return m.isProbed() ? m.getProbeResponseTimeMs() + " ms" : "-";
            case 7: return m.isProbed() ? m.getProbeResponseLength() : 0;
            default: return "";
        }
    }
}
