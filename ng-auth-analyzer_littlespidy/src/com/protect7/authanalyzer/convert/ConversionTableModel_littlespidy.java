// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.convert;

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Thread-safe TableModel for POST to GET conversion results with custom severity rendering.
 *
 * @author littlespidy
 */
public class ConversionTableModel_littlespidy extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final List<ConversionResult_littlespidy> results = new ArrayList<ConversionResult_littlespidy>();

	private static final String[] COLUMN_NAMES = {
			"ID", "Method", "Host", "Path", "POST Status", "GET Status",
			"POST Len", "GET Len", "Content-Type", "Signal", "Severity"
	};

	public synchronized void addResult(ConversionResult_littlespidy result) {
		if (result == null) return;
		results.add(result);
		int idx = results.size() - 1;
		if (SwingUtilities.isEventDispatchThread()) {
			fireTableRowsInserted(idx, idx);
		} else {
			SwingUtilities.invokeLater(() -> fireTableRowsInserted(idx, idx));
		}
	}

	public synchronized void addResults(List<ConversionResult_littlespidy> newResults) {
		if (newResults == null || newResults.isEmpty()) return;
		int start = results.size();
		results.addAll(newResults);
		int end = results.size() - 1;
		if (SwingUtilities.isEventDispatchThread()) {
			fireTableRowsInserted(start, end);
		} else {
			SwingUtilities.invokeLater(() -> fireTableRowsInserted(start, end));
		}
	}

	public synchronized void clear() {
		results.clear();
		if (SwingUtilities.isEventDispatchThread()) {
			fireTableDataChanged();
		} else {
			SwingUtilities.invokeLater(this::fireTableDataChanged);
		}
	}

	public synchronized ConversionResult_littlespidy getResult(int row) {
		if (row >= 0 && row < results.size()) {
			return results.get(row);
		}
		return null;
	}

	public synchronized List<ConversionResult_littlespidy> getAllResults() {
		return new ArrayList<ConversionResult_littlespidy>(results);
	}

	@Override
	public int getRowCount() {
		return results.size();
	}

	@Override
	public int getColumnCount() {
		return COLUMN_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {
		return COLUMN_NAMES[column];
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case 0:
			case 4:
			case 5:
			case 6:
			case 7:
				return Integer.class;
			default:
				return String.class;
		}
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		ConversionResult_littlespidy res = getResult(rowIndex);
		if (res == null) return null;
		switch (columnIndex) {
			case 0: return res.getId();
			case 1: return res.getMethod();
			case 2: return res.getHost();
			case 3: return res.getPath();
			case 4: return res.getPostStatus();
			case 5: return res.getGetStatus();
			case 6: return res.getPostLength();
			case 7: return res.getGetLength();
			case 8: return res.getContentType();
			case 9: return res.getSignal();
			case 10: return res.getSeverity();
			default: return null;
		}
	}

	public static class ConversionCellRenderer extends DefaultTableCellRenderer {
		private static final long serialVersionUID = 1L;

		private static final Color COLOR_HIGH = new Color(255, 60, 60, 75);
		private static final Color COLOR_MEDIUM = new Color(255, 160, 30, 75);
		private static final Color COLOR_LOW = new Color(255, 220, 0, 50);

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean isSelected, boolean hasFocus, int row, int column) {
			Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
			if (!isSelected && table.getModel() instanceof ConversionTableModel_littlespidy) {
				ConversionTableModel_littlespidy model = (ConversionTableModel_littlespidy) table.getModel();
				int modelRow = table.convertRowIndexToModel(row);
				ConversionResult_littlespidy res = model.getResult(modelRow);
				if (res != null) {
					String sev = res.getSeverity();
					if ("High".equalsIgnoreCase(sev)) {
						c.setBackground(COLOR_HIGH);
					} else if ("Medium".equalsIgnoreCase(sev)) {
						c.setBackground(COLOR_MEDIUM);
					} else if ("Low".equalsIgnoreCase(sev)) {
						c.setBackground(COLOR_LOW);
					} else {
						if (row % 2 == 0) {
							c.setBackground(table.getBackground());
						} else {
							c.setBackground(new Color(200, 200, 200, 60));
						}
					}
				}
			}
			return c;
		}
	}
}
