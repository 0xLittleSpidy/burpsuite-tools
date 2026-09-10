// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.ui;

import com.littlespidy.sessionexpiration.model.SessionState;
import com.littlespidy.sessionexpiration.model.SessionTask;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying tracked session tasks in the master view.
 *
 * @author littlespidy
 */
public class SessionTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "#",
            "Method",
            "Host",
            "Path",
            "Baseline",
            "State",
            "Next Check",
            "Milestones",
            "Latest Signal / Verdict"
    };

    private final List<SessionTask> tasks = new ArrayList<>();

    public synchronized void setTasks(List<SessionTask> newTasks) {
        this.tasks.clear();
        if (newTasks != null) {
            this.tasks.addAll(newTasks);
        }
        fireTableDataChanged();
    }

    public synchronized SessionTask getTaskAt(int row) {
        if (row >= 0 && row < tasks.size()) {
            return tasks.get(row);
        }
        return null;
    }

    public synchronized void updateCountdowns() {
        // Fire column 6 ("Next Check") update without clearing row selection or full redraw
        int size = tasks.size();
        if (size > 0) {
            fireTableRowsUpdated(0, size - 1);
        }
    }

    @Override
    public int getRowCount() {
        return tasks.size();
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
                return Integer.class;
            case 5:
                return SessionState.class;
            default:
                return String.class;
        }
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= tasks.size()) {
            return null;
        }
        SessionTask task = tasks.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return task.getId();
            case 1:
                return task.getMethod();
            case 2:
                return task.getHost();
            case 3:
                return task.getPath();
            case 4:
                return task.getBaselineStatusCode() > 0 ? task.getBaselineStatusCode() : 0;
            case 5:
                return task.getState();
            case 6:
                return task.getNextCountdownFormatted();
            case 7:
                return task.getIntervalProgressFormatted();
            case 8:
                return task.getLastVerdict();
            default:
                return null;
        }
    }
}
