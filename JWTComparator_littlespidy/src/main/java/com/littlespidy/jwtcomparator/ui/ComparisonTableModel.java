// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.littlespidy.jwtcomparator.model.ComparisonRow;
import com.littlespidy.jwtcomparator.model.JWTTokenModel;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Dynamic TableModel adapting to N compared JWT tokens.
 */
public class ComparisonTableModel extends AbstractTableModel {

    private final List<JWTTokenModel> tokens = new ArrayList<>();
    private final List<ComparisonRow> displayRows = new ArrayList<>();

    public void setData(List<JWTTokenModel> tokens, List<ComparisonRow> rows) {
        this.tokens.clear();
        if (tokens != null) {
            this.tokens.addAll(tokens);
        }

        this.displayRows.clear();
        if (rows != null) {
            this.displayRows.addAll(rows);
        }

        fireTableStructureChanged();
    }

    public ComparisonRow getRowAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayRows.size()) {
            return displayRows.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return displayRows.size();
    }

    @Override
    public int getColumnCount() {
        // Section, Claim Key, [Token 1..N], Diff Status
        return 2 + tokens.size() + 1;
    }

    @Override
    public String getColumnName(int column) {
        if (column == 0) {
            return "Section";
        } else if (column == 1) {
            return "Claim Key";
        } else if (column >= 2 && column < 2 + tokens.size()) {
            JWTTokenModel t = tokens.get(column - 2);
            return "Token " + t.getSlotIndex() + " (" + t.getLabel() + ")";
        } else {
            return "Diff Status";
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= displayRows.size()) {
            return null;
        }

        ComparisonRow row = displayRows.get(rowIndex);
        if (columnIndex == 0) {
            return row.getSection();
        } else if (columnIndex == 1) {
            return row.getClaimKey();
        } else if (columnIndex >= 2 && columnIndex < 2 + tokens.size()) {
            int slotIndex = tokens.get(columnIndex - 2).getSlotIndex();
            return row.getFormattedValue(slotIndex);
        } else {
            return row.getDiffType().getDisplayName();
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }
}
