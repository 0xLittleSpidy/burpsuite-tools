// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.convert;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

/**
 * Thread-safe TableModel for POST traffic candidates in POST Traffic Discovery.
 *
 * @author littlespidy
 */
public class PostCandidatesTableModel_littlespidy extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final List<PostCandidate_littlespidy> candidates = new ArrayList<PostCandidate_littlespidy>();
	private final Set<Integer> selectedIds = new HashSet<Integer>();

	private static final String[] COLUMN_NAMES = {
			"Select", "#", "Method", "Host", "Path", "Content-Type",
			"Params", "Param Names", "Status", "Length", "Auth Detected"
	};

	@Override
	public int getRowCount() {
		return candidates.size();
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
				return Boolean.class;
			case 1:
			case 6:
			case 8:
			case 9:
				return Integer.class;
			default:
				return String.class;
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return columnIndex == 0;
	}

	@Override
	public synchronized void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		if (columnIndex == 0 && rowIndex >= 0 && rowIndex < candidates.size()) {
			PostCandidate_littlespidy candidate = candidates.get(rowIndex);
			if (Boolean.TRUE.equals(aValue)) {
				selectedIds.add(candidate.getId());
			} else {
				selectedIds.remove(candidate.getId());
			}
			fireTableCellUpdated(rowIndex, columnIndex);
		}
	}

	@Override
	public synchronized Object getValueAt(int rowIndex, int columnIndex) {
		if (rowIndex < 0 || rowIndex >= candidates.size()) return null;
		PostCandidate_littlespidy c = candidates.get(rowIndex);
		switch (columnIndex) {
			case 0: return selectedIds.contains(c.getId());
			case 1: return c.getId();
			case 2: return c.getMethod();
			case 3: return c.getHost();
			case 4: return c.getPath();
			case 5: return c.getContentType();
			case 6: return c.getParameterCount();
			case 7: return String.join(", ", c.getParameterNames());
			case 8: return c.getStatusCode();
			case 9: return c.getContentLength();
			case 10: return c.getAuthIndicator();
			default: return null;
		}
	}

	public synchronized void addCandidate(PostCandidate_littlespidy candidate) {
		if (candidate == null) return;
		candidates.add(candidate);
		selectedIds.add(candidate.getId());
		int idx = candidates.size() - 1;
		if (SwingUtilities.isEventDispatchThread()) {
			fireTableRowsInserted(idx, idx);
		} else {
			SwingUtilities.invokeLater(() -> fireTableRowsInserted(idx, idx));
		}
	}

	public synchronized void addCandidates(List<PostCandidate_littlespidy> newCandidates) {
		if (newCandidates == null || newCandidates.isEmpty()) return;
		int start = candidates.size();
		for (PostCandidate_littlespidy c : newCandidates) {
			candidates.add(c);
			selectedIds.add(c.getId());
		}
		int end = candidates.size() - 1;
		if (SwingUtilities.isEventDispatchThread()) {
			fireTableRowsInserted(start, end);
		} else {
			SwingUtilities.invokeLater(() -> fireTableRowsInserted(start, end));
		}
	}

	public synchronized void clear() {
		candidates.clear();
		selectedIds.clear();
		if (SwingUtilities.isEventDispatchThread()) {
			fireTableDataChanged();
		} else {
			SwingUtilities.invokeLater(this::fireTableDataChanged);
		}
	}

	public synchronized PostCandidate_littlespidy getCandidate(int row) {
		if (row >= 0 && row < candidates.size()) {
			return candidates.get(row);
		}
		return null;
	}

	public synchronized List<PostCandidate_littlespidy> getSelectedCandidates() {
		List<PostCandidate_littlespidy> selected = new ArrayList<PostCandidate_littlespidy>();
		for (PostCandidate_littlespidy c : candidates) {
			if (selectedIds.contains(c.getId())) {
				selected.add(c);
			}
		}
		return selected;
	}

	public synchronized void selectAll(boolean select) {
		if (select) {
			for (PostCandidate_littlespidy c : candidates) {
				selectedIds.add(c.getId());
			}
		} else {
			selectedIds.clear();
		}
		fireTableDataChanged();
	}

	public synchronized List<PostCandidate_littlespidy> getAllCandidates() {
		return new ArrayList<PostCandidate_littlespidy>(candidates);
	}
}
