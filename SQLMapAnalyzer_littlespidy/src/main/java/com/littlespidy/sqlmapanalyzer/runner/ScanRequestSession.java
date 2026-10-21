// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.runner;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Manages an individual HTTP request target and all its historical scan executions.
 * Plain ASCII text only.
 */
public class ScanRequestSession implements Serializable {
    private static final long serialVersionUID = 1L;

    private int sessionId;
    private String customTabTitle = null;
    private String method = "GET";
    private String url = "";
    private byte[] rawRequest = new byte[0];
    private final List<ScanExecutionRecord> executions = new ArrayList<>();
    private int currentExecutionIndex = 0;

    public ScanRequestSession(int sessionId, String method, String url, byte[] rawRequest, SqlmapTaskOptions initialOptions) {
        this.sessionId = sessionId;
        this.method = method != null ? method.toUpperCase() : "GET";
        this.url = url != null ? url : "";
        this.rawRequest = rawRequest != null ? rawRequest : new byte[0];

        // Create initial Execution Run #1
        ScanExecutionRecord firstRun = new ScanExecutionRecord(1, initialOptions);
        this.executions.add(firstRun);
        this.currentExecutionIndex = 0;
    }

    public int getSessionId() {
        return sessionId;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public byte[] getRawRequest() {
        return rawRequest;
    }

    public synchronized List<ScanExecutionRecord> getExecutions() {
        return Collections.unmodifiableList(executions);
    }

    public synchronized ScanExecutionRecord getActiveExecution() {
        if (executions.isEmpty()) return null;
        if (currentExecutionIndex < 0 || currentExecutionIndex >= executions.size()) {
            currentExecutionIndex = executions.size() - 1;
        }
        return executions.get(currentExecutionIndex);
    }

    public synchronized void setActiveExecutionIndex(int index) {
        if (index >= 0 && index < executions.size()) {
            this.currentExecutionIndex = index;
        }
    }

    public synchronized int getActiveExecutionIndex() {
        return currentExecutionIndex;
    }

    public synchronized ScanExecutionRecord createNewExecution() {
        int nextNum = executions.size() + 1;
        SqlmapTaskOptions prevOptions = getActiveExecution() != null
                ? new SqlmapTaskOptions(getActiveExecution().getOptions())
                : new SqlmapTaskOptions();
        ScanExecutionRecord newRun = new ScanExecutionRecord(nextNum, prevOptions);
        executions.add(newRun);
        currentExecutionIndex = executions.size() - 1;
        return newRun;
    }

    public synchronized boolean deleteExecution(int index) {
        if (executions.size() <= 1) {
            return false; // Keep at least one execution
        }
        if (index >= 0 && index < executions.size()) {
            executions.remove(index);
            if (currentExecutionIndex >= executions.size()) {
                currentExecutionIndex = executions.size() - 1;
            }
            return true;
        }
        return false;
    }

    public synchronized void setCustomTabTitle(String customTabTitle) {
        this.customTabTitle = customTabTitle;
    }

    public synchronized String getCustomTabTitle() {
        return customTabTitle;
    }

    public synchronized String getTabTitle() {
        if (customTabTitle != null && !customTabTitle.isBlank()) {
            return customTabTitle;
        }
        String path = url;
        try {
            URI u = URI.create(url);
            path = u.getPath();
            if (path == null || path.isBlank()) path = "/";
            if (u.getQuery() != null && !u.getQuery().isBlank()) {
                path += "?" + u.getQuery();
            }
        } catch (Exception ignored) {}

        if (path.length() > 30) {
            path = path.substring(0, 27) + "...";
        }
        return "#" + sessionId + " " + method + " " + path;
    }
}
