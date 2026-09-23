// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.ui;

import com.littlespidy.sessionexpiration.model.ProbeResult;
import com.littlespidy.sessionexpiration.model.SessionTask;
import com.littlespidy.sessionexpiration.model.TimerInterval;

import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model displaying milestone intervals, execution results, and server response dates
 * for the selected SessionTask.
 *
 * @author littlespidy
 */
public class ProbeHistoryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
            "Milestone",
            "Scheduled Time",
            "Executed Time",
            "Server Date",
            "Status",
            "HTTP Status",
            "Length (Bytes)",
            "Response Time",
            "Signal / Verdict"
    };

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final List<TimerInterval> intervals = new ArrayList<>();
    private SessionTask currentTask;

    public synchronized void setTask(SessionTask task) {
        this.currentTask = task;
        this.intervals.clear();
        if (task != null && task.getIntervals() != null) {
            this.intervals.addAll(task.getIntervals());
        }
        fireTableDataChanged();
    }

    public synchronized TimerInterval getIntervalAt(int row) {
        if (row >= 0 && row < intervals.size()) {
            return intervals.get(row);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return intervals.size();
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
            case 4:
                return TimerInterval.IntervalStatus.class;
            case 5:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= intervals.size()) {
            return null;
        }
        TimerInterval interval = intervals.get(rowIndex);
        ProbeResult pr = interval.getProbeResult();

        switch (columnIndex) {
            case 0:
                return interval.getLabel();
            case 1:
                return formatTime(interval.getScheduledTargetTime());
            case 2:
                return formatTime(interval.getExecutedTime());
            case 3:
                return (pr != null && pr.getServerDate() != null) ? pr.getServerDate() : "-";
            case 4:
                return interval.getStatus();
            case 5:
                return (pr != null) ? pr.getStatusCode() : 0;
            case 6:
                if (pr != null) {
                    long len = pr.getResponseLength();
                    if (currentTask != null && currentTask.getBaselineLength() > 0) {
                        long diff = len - currentTask.getBaselineLength();
                        String sign = diff > 0 ? "+" : "";
                        return len + " (" + sign + diff + ")";
                    }
                    return String.valueOf(len);
                }
                return "-";
            case 7:
                return (pr != null) ? (pr.getDurationMillis() + " ms") : "-";
            case 8:
                if (pr != null) {
                    return pr.getSignal();
                }
                if (interval.getStatus() == TimerInterval.IntervalStatus.SCHEDULED) {
                    return "Pending scheduled execution";
                }
                return interval.getStatus().toString();
            default:
                return null;
        }
    }

    private String formatTime(Instant instant) {
        if (instant == null) return "-";
        try {
            return TIME_FORMATTER.format(instant);
        } catch (Exception e) {
            return instant.toString();
        }
    }
}
