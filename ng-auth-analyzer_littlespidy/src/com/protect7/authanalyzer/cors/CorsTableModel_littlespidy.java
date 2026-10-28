// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.cors;

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy.CorsSeverity;

public class CorsTableModel_littlespidy extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final List<CorsTestResult_littlespidy> results = new ArrayList<CorsTestResult_littlespidy>();

	private static final String[] COLUMN_NAMES = {
			"ID", "Host", "Path", "Test Vector", "Tested Origin",
			"Reflected ACAO", "ACAC", "Status Code", "Length"
	};

	public synchronized void addResult(CorsTestResult_littlespidy result) {
		results.add(result);
		int idx = results.size() - 1;
		if (SwingUtilities.isEventDispatchThread()) {
			fireTableRowsInserted(idx, idx);
		} else {
			SwingUtilities.invokeLater(() -> fireTableRowsInserted(idx, idx));
		}
	}

	public synchronized void addResults(List<CorsTestResult_littlespidy> newResults) {
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

	public synchronized CorsTestResult_littlespidy getResult(int row) {
		if (row >= 0 && row < results.size()) {
			return results.get(row);
		}
		return null;
	}

	public synchronized List<CorsTestResult_littlespidy> getAllResults() {
		return new ArrayList<CorsTestResult_littlespidy>(results);
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
			case 7:
			case 8:
				return Integer.class;
			case 6:
				return Boolean.class;
			default:
				return String.class;
		}
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		CorsTestResult_littlespidy res = getResult(rowIndex);
		if (res == null) return null;
		switch (columnIndex) {
			case 0: return res.getId();
			case 1: return res.getHost();
			case 2: return res.getPath();
			case 3: return res.getTestTypeDescription();
			case 4: return res.getTestedOrigin();
			case 5: return res.getReflectedAcao();
			case 6: return res.isAcacPresent();
			case 7: return res.getStatusCode();
			case 8: return res.getLength();
			default: return null;
		}
	}

	public static class CorsCellRenderer extends DefaultTableCellRenderer {
		private static final long serialVersionUID = 1L;

		private static final Color COLOR_HIGH = new Color(255, 60, 60, 75);
		private static final Color COLOR_MEDIUM = new Color(255, 160, 30, 75);
		private static final Color COLOR_LOW = new Color(255, 220, 0, 50);
		private static final Color COLOR_SECURE = new Color(46, 204, 113, 50);

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean isSelected, boolean hasFocus, int row, int column) {
			Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
			if (!isSelected && table.getModel() instanceof CorsTableModel_littlespidy) {
				CorsTableModel_littlespidy model = (CorsTableModel_littlespidy) table.getModel();
				int modelRow = table.convertRowIndexToModel(row);
				CorsTestResult_littlespidy res = model.getResult(modelRow);
				if (res != null) {
					if (res.getSeverity() == CorsSeverity.HIGH) {
						c.setBackground(COLOR_HIGH);
					} else if (res.getSeverity() == CorsSeverity.MEDIUM) {
						c.setBackground(COLOR_MEDIUM);
					} else if (res.getSeverity() == CorsSeverity.LOW) {
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
