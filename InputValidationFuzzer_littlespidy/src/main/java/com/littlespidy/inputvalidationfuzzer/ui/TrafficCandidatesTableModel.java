package com.littlespidy.inputvalidationfuzzer.ui;

import com.littlespidy.inputvalidationfuzzer.model.TrafficCandidate;

import javax.swing.table.AbstractTableModel;
import java.util.*;
import java.util.function.Predicate;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe table model for traffic candidates in the Traffic Sweep tab.
 *
 * @author littlespidy
 */
public class TrafficCandidatesTableModel extends AbstractTableModel {
    private final String[] columnNames = {
        "Select", "#", "Method", "Host", "Path", "Params", "Param Names", "Status", "Length", "Auth Detected"
    };

    private final Class<?>[] columnClasses = {
        Boolean.class, Integer.class, String.class, String.class, String.class, Integer.class, String.class, Integer.class, Integer.class, String.class
    };

    private final List<TrafficCandidate> allCandidates = new ArrayList<>();
    private final List<TrafficCandidate> filteredCandidates = new ArrayList<>();
    private final Set<Integer> selectedCandidateIds = new HashSet<>();
    private Predicate<TrafficCandidate> currentFilter = c -> true;

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
            TrafficCandidate c = filteredCandidates.get(rowIndex);
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

        TrafficCandidate c = filteredCandidates.get(rowIndex);
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

    public synchronized TrafficCandidate getCandidateAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < filteredCandidates.size()) {
            return filteredCandidates.get(rowIndex);
        }
        return null;
    }

    public synchronized List<TrafficCandidate> getSelectedCandidates() {
        List<TrafficCandidate> selected = new ArrayList<>();
        for (TrafficCandidate c : allCandidates) {
            if (selectedCandidateIds.contains(c.id())) {
                selected.add(c);
            }
        }
        return selected;
    }

    public synchronized void selectAll(boolean select) {
        if (select) {
            for (TrafficCandidate c : filteredCandidates) {
                selectedCandidateIds.add(c.id());
            }
        } else {
            selectedCandidateIds.clear();
        }
        fireTableDataChanged();
    }

    public synchronized void setCandidates(List<TrafficCandidate> candidates) {
        this.allCandidates.clear();
        this.allCandidates.addAll(candidates);
        applyCurrentFilter();
    }

    public synchronized void setFilter(Predicate<TrafficCandidate> filter) {
        this.currentFilter = (filter != null) ? filter : c -> true;
        applyCurrentFilter();
    }

    private void applyCurrentFilter() {
        filteredCandidates.clear();
        for (TrafficCandidate c : allCandidates) {
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

    public synchronized List<TrafficCandidate> getFilteredCandidates() {
        return new ArrayList<>(filteredCandidates);
    }

    public synchronized List<TrafficCandidate> getAllCandidates() {
        return new ArrayList<>(allCandidates);
    }
}
