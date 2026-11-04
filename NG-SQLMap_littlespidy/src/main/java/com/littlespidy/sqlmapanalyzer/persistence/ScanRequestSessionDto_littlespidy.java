// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.persistence;

import com.littlespidy.sqlmapanalyzer.runner.ScanExecutionRecord;
import com.littlespidy.sqlmapanalyzer.runner.ScanRequestSession;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Serializable DTO for persisting a ScanRequestSession and all its execution runs in session JSON.
 * Plain ASCII text only.
 */
public class ScanRequestSessionDto_littlespidy implements Serializable {
    private static final long serialVersionUID = 1L;

    private int sessionId;
    private String customTabTitle;
    private String method = "GET";
    private String url = "";
    private String rawRequestBase64 = "";
    private int currentExecutionIndex = 0;
    private List<ScanExecutionRecord> executions = new ArrayList<>();

    public ScanRequestSessionDto_littlespidy() {}

    public static ScanRequestSessionDto_littlespidy fromSession(ScanRequestSession session) {
        if (session == null) return null;
        ScanRequestSessionDto_littlespidy dto = new ScanRequestSessionDto_littlespidy();
        dto.sessionId = session.getSessionId();
        dto.customTabTitle = session.getCustomTabTitle();
        dto.method = session.getMethod();
        dto.url = session.getUrl();
        if (session.getRawRequest() != null && session.getRawRequest().length > 0) {
            dto.rawRequestBase64 = Base64.getEncoder().encodeToString(session.getRawRequest());
        }
        dto.currentExecutionIndex = session.getActiveExecutionIndex();
        dto.executions = new ArrayList<>(session.getExecutions());
        return dto;
    }

    public ScanRequestSession toSession() {
        byte[] rawBytes = new byte[0];
        if (rawRequestBase64 != null && !rawRequestBase64.isBlank()) {
            try {
                rawBytes = Base64.getDecoder().decode(rawRequestBase64);
            } catch (Exception ignored) {}
        }

        ScanRequestSession session = new ScanRequestSession(sessionId, method, url, rawBytes, null);
        if (customTabTitle != null && !customTabTitle.isBlank()) {
            session.setCustomTabTitle(customTabTitle);
        }

        if (executions != null && !executions.isEmpty()) {
            session.restoreExecutions(executions, currentExecutionIndex);
        }
        return session;
    }

    public int getSessionId() { return sessionId; }
    public void setSessionId(int sessionId) { this.sessionId = sessionId; }
    public String getCustomTabTitle() { return customTabTitle; }
    public void setCustomTabTitle(String customTabTitle) { this.customTabTitle = customTabTitle; }
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getRawRequestBase64() { return rawRequestBase64; }
    public void setRawRequestBase64(String rawRequestBase64) { this.rawRequestBase64 = rawRequestBase64; }
    public int getCurrentExecutionIndex() { return currentExecutionIndex; }
    public void setCurrentExecutionIndex(int currentExecutionIndex) { this.currentExecutionIndex = currentExecutionIndex; }
    public List<ScanExecutionRecord> getExecutions() { return executions; }
    public void setExecutions(List<ScanExecutionRecord> executions) { this.executions = executions; }
}
