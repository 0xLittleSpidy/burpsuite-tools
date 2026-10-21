// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.runner;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapFinding;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Tracks the state, options, real-time logs, and findings for a single scan execution run.
 * Plain ASCII text only.
 */
public class ScanExecutionRecord implements Serializable {
    private static final long serialVersionUID = 1L;

    private int executionNumber;
    private long timestamp;
    private String taskId = "";
    private SqlmapTaskOptions options;
    private String status = "READY";
    private boolean vulnerable = false;
    private final List<SqlmapLogEntry> logs = new ArrayList<>();
    private final List<SqlmapFinding> findings = new ArrayList<>();

    public ScanExecutionRecord(int executionNumber, SqlmapTaskOptions initialOptions) {
        this.executionNumber = executionNumber;
        this.timestamp = System.currentTimeMillis();
        this.options = initialOptions != null ? initialOptions : new SqlmapTaskOptions();
    }

    public int getExecutionNumber() {
        return executionNumber;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getTaskId() {
        return taskId;
    }

    public void setTaskId(String taskId) {
        this.taskId = taskId != null ? taskId : "";
    }

    public SqlmapTaskOptions getOptions() {
        return options;
    }

    public void setOptions(SqlmapTaskOptions options) {
        this.options = options != null ? options : new SqlmapTaskOptions();
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status != null ? status : "READY";
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public void setVulnerable(boolean vulnerable) {
        this.vulnerable = vulnerable;
    }

    public synchronized List<SqlmapLogEntry> getLogs() {
        return new ArrayList<>(logs);
    }

    public synchronized void addLog(SqlmapLogEntry entry) {
        if (entry != null) logs.add(entry);
    }

    public synchronized void setLogs(List<SqlmapLogEntry> newLogs) {
        logs.clear();
        if (newLogs != null) logs.addAll(newLogs);
    }

    public synchronized List<SqlmapFinding> getFindings() {
        return new ArrayList<>(findings);
    }

    public synchronized void addFinding(SqlmapFinding finding) {
        if (finding != null) {
            findings.add(finding);
            if (finding.getType() == 1 || finding.getDetails().toLowerCase().contains("injection")) {
                this.vulnerable = true;
            }
        }
    }

    public synchronized void setFindings(List<SqlmapFinding> newFindings) {
        findings.clear();
        if (newFindings != null) {
            findings.addAll(newFindings);
            for (SqlmapFinding f : newFindings) {
                if (f.getType() == 1 || f.getDetails().toLowerCase().contains("injection")) {
                    this.vulnerable = true;
                }
            }
        }
    }

    public String getDisplayName() {
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        String timeStr = sdf.format(new Date(timestamp));
        String resultTag = vulnerable ? " [VULNERABLE]" : " [" + status + "]";
        return "Run #" + executionNumber + " (" + timeStr + ")" + resultTag;
    }

    @Override
    public String toString() {
        return getDisplayName();
    }
}
