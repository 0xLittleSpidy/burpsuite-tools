// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.model;

import java.io.Serializable;

public class AuditFinding_littlespidy implements Serializable {
    private static final long serialVersionUID = 1L;

    private String id;
    private AuditProbeType_littlespidy probeType;
    private AuditSeverity_littlespidy severity;
    private String title;
    private String description;
    private String recommendation;
    private String impact;
    private String endpointUrl;
    private String requestBase64;
    private String responseBase64;
    private long timestamp;

    public AuditFinding_littlespidy() {
        this.timestamp = System.currentTimeMillis();
    }

    public AuditFinding_littlespidy(String id, AuditProbeType_littlespidy probeType, AuditSeverity_littlespidy severity,
                                   String title, String description, String recommendation, String impact,
                                   String endpointUrl, String requestBase64, String responseBase64) {
        this.id = id;
        this.probeType = probeType;
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.recommendation = recommendation;
        this.impact = impact;
        this.endpointUrl = endpointUrl;
        this.requestBase64 = requestBase64;
        this.responseBase64 = responseBase64;
        this.timestamp = System.currentTimeMillis();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public AuditProbeType_littlespidy getProbeType() { return probeType; }
    public void setProbeType(AuditProbeType_littlespidy probeType) { this.probeType = probeType; }

    public AuditSeverity_littlespidy getSeverity() { return severity; }
    public void setSeverity(AuditSeverity_littlespidy severity) { this.severity = severity; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }

    public String getImpact() { return impact; }
    public void setImpact(String impact) { this.impact = impact; }

    public String getEndpointUrl() { return endpointUrl; }
    public void setEndpointUrl(String endpointUrl) { this.endpointUrl = endpointUrl; }

    public String getRequestBase64() { return requestBase64; }
    public void setRequestBase64(String requestBase64) { this.requestBase64 = requestBase64; }

    public String getResponseBase64() { return responseBase64; }
    public void setResponseBase64(String responseBase64) { this.responseBase64 = responseBase64; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
}
