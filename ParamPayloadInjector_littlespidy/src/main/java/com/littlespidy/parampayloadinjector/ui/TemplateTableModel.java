package com.littlespidy.parampayloadinjector.ui;

import com.littlespidy.parampayloadinjector.model.InjectionConfig;
import com.littlespidy.parampayloadinjector.model.PayloadTemplate;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Table model for managing and viewing payload templates.
 */
public class TemplateTableModel extends AbstractTableModel {

    private final InjectionConfig config;
    private final String[] columns = {"Enabled", "Category", "Name", "Template", "Description"};

    public TemplateTableModel(InjectionConfig config) {
        this.config = config;
        this.config.addChangeListener(this::fireTableDataChanged);
    }

    @Override
    public int getRowCount() {
        return config.getTemplates().size();
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
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) return Boolean.class;
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        List<PayloadTemplate> templates = config.getTemplates();
        if (rowIndex < 0 || rowIndex >= templates.size()) return null;

        PayloadTemplate t = templates.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> t.isEnabled();
            case 1 -> t.getCategory();
            case 2 -> t.getName();
            case 3 -> t.getTemplate();
            case 4 -> t.getDescription();
            default -> null;
        };
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        List<PayloadTemplate> templates = config.getTemplates();
        if (rowIndex < 0 || rowIndex >= templates.size()) return;

        PayloadTemplate t = templates.get(rowIndex);
        if (columnIndex == 0 && aValue instanceof Boolean) {
            t.setEnabled((Boolean) aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }

    public PayloadTemplate getTemplateAt(int rowIndex) {
        List<PayloadTemplate> templates = config.getTemplates();
        if (rowIndex >= 0 && rowIndex < templates.size()) {
            return templates.get(rowIndex);
        }
        return null;
    }
}
