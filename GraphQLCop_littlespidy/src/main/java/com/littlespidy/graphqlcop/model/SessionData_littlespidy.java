// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class SessionData_littlespidy implements Serializable {
    private static final long serialVersionUID = 1L;

    private String sessionId;
    private String tabTitle;
    private String targetUrl;
    private String customHeaders;
    private String queryEditorContent;
    private String variablesEditorContent;
    private String rawIntrospectionJson;
    private List<AuditFinding_littlespidy> findings = new ArrayList<>();
    private List<HttpLogEntry_littlespidy> httpLogs = new ArrayList<>();

    public SessionData_littlespidy() {}

    public SessionData_littlespidy(String sessionId, String tabTitle, String targetUrl) {
        this.sessionId = sessionId;
        this.tabTitle = tabTitle;
        this.targetUrl = targetUrl;
        this.customHeaders = "";
        this.queryEditorContent = "";
        this.variablesEditorContent = "";
        this.rawIntrospectionJson = "";
    }

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public String getTabTitle() { return tabTitle; }
    public void setTabTitle(String tabTitle) { this.tabTitle = tabTitle; }

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

    public String getCustomHeaders() { return customHeaders; }
    public void setCustomHeaders(String customHeaders) { this.customHeaders = customHeaders; }

    public String getQueryEditorContent() { return queryEditorContent; }
    public void setQueryEditorContent(String queryEditorContent) { this.queryEditorContent = queryEditorContent; }

    public String getVariablesEditorContent() { return variablesEditorContent; }
    public void setVariablesEditorContent(String variablesEditorContent) { this.variablesEditorContent = variablesEditorContent; }

    public String getRawIntrospectionJson() { return rawIntrospectionJson; }
    public void setRawIntrospectionJson(String rawIntrospectionJson) { this.rawIntrospectionJson = rawIntrospectionJson; }

    public List<AuditFinding_littlespidy> getFindings() { return findings; }
    public void setFindings(List<AuditFinding_littlespidy> findings) { this.findings = findings; }

    public List<HttpLogEntry_littlespidy> getHttpLogs() { return httpLogs; }
    public void setHttpLogs(List<HttpLogEntry_littlespidy> httpLogs) { this.httpLogs = httpLogs; }
}
