// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class OAuthRequestEntry {

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final int id;
    private final String timestamp;
    private final HttpRequestResponse originalRequestResponse;
    private final String method;
    private final String host;
    private final String path;
    private final String url;
    private final int statusCode;

    private OAuthFlowType flowType;
    private List<OAuthParam> parameters;
    private final List<SSOAuditIssue> issues;

    public OAuthRequestEntry(int id, HttpRequestResponse requestResponse) {
        this(id, null, requestResponse);
    }

    public OAuthRequestEntry(int id, String timestamp, HttpRequestResponse requestResponse) {
        this.id = id;
        this.timestamp = (timestamp != null && !timestamp.isBlank()) ? timestamp : LocalTime.now().format(TIME_FORMAT);
        this.originalRequestResponse = requestResponse;
        this.issues = new ArrayList<>();
        this.parameters = new ArrayList<>();
        this.flowType = OAuthFlowType.UNKNOWN_OR_CUSTOM;

        if (requestResponse != null && requestResponse.request() != null) {
            this.method = requestResponse.request().method();
            this.url = requestResponse.request().url();
            this.path = requestResponse.request().path();
            this.host = requestResponse.request().httpService() != null ? requestResponse.request().httpService().host() : "";
        } else {
            this.method = "UNKNOWN";
            this.url = "";
            this.path = "";
            this.host = "";
        }

        if (requestResponse != null && requestResponse.hasResponse() && requestResponse.response() != null) {
            this.statusCode = requestResponse.response().statusCode();
        } else {
            this.statusCode = 0;
        }
    }

    public int getId() {
        return id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public HttpRequestResponse getOriginalRequestResponse() {
        return originalRequestResponse;
    }

    public String getMethod() {
        return method;
    }

    public String getHost() {
        return host;
    }

    public String getPath() {
        return path;
    }

    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public synchronized OAuthFlowType getFlowType() {
        return flowType;
    }

    public synchronized void setFlowType(OAuthFlowType flowType) {
        this.flowType = flowType != null ? flowType : OAuthFlowType.UNKNOWN_OR_CUSTOM;
    }

    public synchronized List<OAuthParam> getParameters() {
        return Collections.unmodifiableList(new ArrayList<>(parameters));
    }

    public synchronized void setParameters(List<OAuthParam> params) {
        this.parameters = params != null ? new ArrayList<>(params) : new ArrayList<>();
    }

    public synchronized List<SSOAuditIssue> getIssues() {
        return Collections.unmodifiableList(new ArrayList<>(issues));
    }

    public synchronized void setIssues(List<SSOAuditIssue> newIssues) {
        this.issues.clear();
        if (newIssues != null) {
            this.issues.addAll(newIssues);
        }
    }

    public synchronized void addIssue(SSOAuditIssue issue) {
        if (issue != null) {
            // Avoid adding identical issues with duplicate titles
            boolean exists = issues.stream().anyMatch(i -> i.getTitle().equalsIgnoreCase(issue.getTitle()));
            if (!exists) {
                issues.add(issue);
            }
        }
    }

    public synchronized void clearIssues() {
        this.issues.clear();
    }

    public synchronized IssueSeverity getHighestSeverity() {
        if (issues.isEmpty()) {
            return IssueSeverity.CLEAN;
        }
        IssueSeverity highest = IssueSeverity.INFORMATION;
        for (SSOAuditIssue issue : issues) {
            if (issue.getSeverity().getRank() > highest.getRank()) {
                highest = issue.getSeverity();
            }
        }
        return highest;
    }

    public synchronized int getIssuesCount() {
        return issues.size();
    }

    public synchronized String getIssueSummary() {
        if (issues.isEmpty()) {
            return "No issues detected";
        }
        return issues.stream()
                .map(SSOAuditIssue::getTitle)
                .collect(Collectors.joining("; "));
    }

    public synchronized String getParamValue(String paramName) {
        if (paramName == null) return null;
        for (OAuthParam p : parameters) {
            if (p.getName().equalsIgnoreCase(paramName)) {
                return p.getRawValue();
            }
        }
        return null;
    }

    public synchronized String getClientId() {
        String val = getParamValue("client_id");
        return val != null ? val : "";
    }

    public synchronized String getRedirectUri() {
        String val = getParamValue("redirect_uri");
        return val != null ? val : "";
    }
}
