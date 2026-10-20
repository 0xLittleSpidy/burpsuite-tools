// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.ui;

import com.littlespidy.ssoinspector.model.OAuthParam;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class OAuthParamTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "Parameter",
            "Location",
            "Value",
            "Decoded / Structured Value",
            "Standard IANA",
            "Description"
    };

    private static final Class<?>[] COLUMN_CLASSES = {
            String.class,
            String.class,
            String.class,
            String.class,
            Boolean.class,
            String.class
    };

    private List<OAuthParam> parameters;

    public OAuthParamTableModel() {
        this.parameters = new ArrayList<>();
    }

    public synchronized void setParameters(List<OAuthParam> params) {
        this.parameters = params != null ? new ArrayList<>(params) : new ArrayList<>();
        fireTableDataChanged();
    }

    public synchronized OAuthParam getParamAt(int row) {
        if (row >= 0 && row < parameters.size()) {
            return parameters.get(row);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return parameters.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMN_NAMES[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_CLASSES[columnIndex];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        OAuthParam param = getParamAt(rowIndex);
        if (param == null) return null;

        return switch (columnIndex) {
            case 0 -> param.getName();
            case 1 -> param.getLocation().getLabel();
            case 2 -> param.getRawValue();
            case 3 -> param.getDecodedValue();
            case 4 -> param.isStandard();
            case 5 -> param.getDescription();
            default -> null;
        };
    }
}
