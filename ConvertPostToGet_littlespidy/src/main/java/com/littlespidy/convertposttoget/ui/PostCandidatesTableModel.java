package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.model.PostCandidate;

import javax.swing.table.AbstractTableModel;
import java.util.*;
import java.util.function.Predicate;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe table model for POST traffic candidates.
 *
 * @author littlespidy
 */
public class PostCandidatesTableModel extends AbstractTableModel {
    private final String[] columnNames = {
        "Select", "#", "Method", "Host", "Path", "Params", "Param Names", "POST Status", "Length", "Auth Detected"
    };

    private final Class<?>[] columnClasses = {
        Boolean.class, Integer.class, String.class, String.class, String.class, Integer.class, String.class, Integer.class, Integer.class, String.class
    };

    private final List<PostCandidate> allCandidates = new ArrayList<>();
    private final List<PostCandidate> filteredCandidates = new ArrayList<>();
    private final Set<Integer> selectedCandidateIds = new HashSet<>();
    private Predicate<PostCandidate> currentFilter = c -> true;

    @Override
    public synchronized int getRowCount() {
        return filteredCandidates.size();
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
        return columnClasses[columnIndex];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public synchronized void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0 && rowIndex >= 0 && rowIndex < filteredCandidates.size()) {
            PostCandidate c = filteredCandidates.get(rowIndex);
            if (Boolean.TRUE.equals(aValue)) {
                selectedCandidateIds.add(c.id());
            } else {
                selectedCandidateIds.remove(c.id());
            }
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= filteredCandidates.size()) {
            return null;
        }

        PostCandidate c = filteredCandidates.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> selectedCandidateIds.contains(c.id());
            case 1 -> c.id();
            case 2 -> c.method();
            case 3 -> c.host();
            case 4 -> c.path();
            case 5 -> c.parameterCount();
            case 6 -> String.join(", ", c.parameterNames());
            case 7 -> c.statusCode();
            case 8 -> c.contentLength();
            case 9 -> c.authIndicator();
            default -> null;
        };
    }

    public synchronized PostCandidate getCandidateAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < filteredCandidates.size()) {
            return filteredCandidates.get(rowIndex);
        }
        return null;
    }

    public synchronized List<PostCandidate> getSelectedCandidates() {
        List<PostCandidate> selected = new ArrayList<>();
        for (PostCandidate c : allCandidates) {
            if (selectedCandidateIds.contains(c.id())) {
                selected.add(c);
            }
        }
        return selected;
    }

    public synchronized void selectAll(boolean select) {
        if (select) {
            for (PostCandidate c : filteredCandidates) {
                selectedCandidateIds.add(c.id());
            }
        } else {
            selectedCandidateIds.clear();
        }
        fireTableDataChanged();
    }

    public synchronized void setCandidates(List<PostCandidate> candidates) {
        this.allCandidates.clear();
        this.allCandidates.addAll(candidates);
        applyCurrentFilter();
    }

    public synchronized void setFilter(Predicate<PostCandidate> filter) {
        this.currentFilter = (filter != null) ? filter : c -> true;
        applyCurrentFilter();
    }

    private void applyCurrentFilter() {
        filteredCandidates.clear();
        for (PostCandidate c : allCandidates) {
            if (currentFilter.test(c)) {
                filteredCandidates.add(c);
            }
        }
        fireTableDataChanged();
    }

    public synchronized void clear() {
        allCandidates.clear();
        filteredCandidates.clear();
        selectedCandidateIds.clear();
        fireTableDataChanged();
    }

    public synchronized int getAllCandidatesCount() {
        return allCandidates.size();
    }

    public synchronized List<PostCandidate> getFilteredCandidates() {
        return new ArrayList<>(filteredCandidates);
    }

    public synchronized List<PostCandidate> getAllCandidates() {
        return new ArrayList<>(allCandidates);
    }
}
