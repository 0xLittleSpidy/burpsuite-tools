// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.util;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;

public class BypassCellRenderer extends DefaultTableCellRenderer {

	private static final long serialVersionUID = 1L;
	private static final Color COLOR_STATUS_CODE = new Color(64, 150, 255, 40);
	private static final Color COLOR_LENGTH = new Color(46, 204, 113, 40);
	private static final Color COLOR_DIFF = new Color(243, 156, 18, 40);

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
			int row, int column) {
		Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
		if (value instanceof BypassConstants && !value.toString().equals(BypassConstants.NA.toString())) {
			BypassConstants bypassConstant = (BypassConstants) value;
			if (bypassConstant == BypassConstants.SAME) {
				if (!isSelected) {
					c.setBackground(new Color(255, 51, 51, 80));
				}
			}
			if (bypassConstant == BypassConstants.SIMILAR) {
				if (!isSelected) {
					c.setBackground(new Color(255, 153, 0, 80));
				}
			}
			if (bypassConstant == BypassConstants.DIFFERENT) {
				if (!isSelected) {
					c.setBackground(new Color(0, 255, 51, 80));
				}
			}
		}
		else {
			RequestTableModel tableModel = (RequestTableModel) table.getModel();
			OriginalRequestResponse requestResponse = null;
			try {
				int modelRow = table.convertRowIndexToModel(row);
				requestResponse = tableModel.getOriginalRequestResponse(modelRow);
			} catch (Exception ex) {
				// Index out of range protection
			}
			if(requestResponse != null && requestResponse.isMarked()) {
				if(!isSelected) {
					c.setBackground(new Color(255, 255, 0, 120));
				}
				else {
					c.setBackground(new Color(210, 210, 0, 120));
				}
			}
			else {
				if(!isSelected) {
					String colName = "";
					try {
						colName = table.getColumnName(column);
					} catch (Exception ignored) {}

					if (colName.endsWith("Status Code") || colName.equals("Original Status Code")) {
						c.setBackground(COLOR_STATUS_CODE);
					} else if (colName.endsWith("Length") || colName.equals("Original Length")) {
						c.setBackground(COLOR_LENGTH);
					} else if (colName.endsWith("Diff") || colName.equals("Original Diff")) {
						c.setBackground(COLOR_DIFF);
					} else {
						if(row % 2 == 0) {
							c.setBackground(table.getBackground());
						}
						else {
							c.setBackground(new Color(200, 200, 200, 80));
						}
					}
				}
			}
		}
		return c;
	}
}