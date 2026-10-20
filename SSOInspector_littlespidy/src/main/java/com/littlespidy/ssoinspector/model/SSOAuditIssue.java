// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.Collections;
import java.util.List;

public class SSOAuditIssue {

    private final String title;
    private final IssueSeverity severity;
    private final IssueConfidence confidence;
    private final String description;
    private final String remediation;
    private final String references;
    private final HttpRequestResponse httpMessage;
    private final boolean activeProbe;

    public SSOAuditIssue(String title, IssueSeverity severity, IssueConfidence confidence,
                         String description, String remediation, String references,
                         HttpRequestResponse httpMessage, boolean activeProbe) {
        this.title = title != null ? title : "OAuth Issue";
        this.severity = severity != null ? severity : IssueSeverity.INFORMATION;
        this.confidence = confidence != null ? confidence : IssueConfidence.TENTATIVE;
        this.description = description != null ? description : "";
        this.remediation = remediation != null ? remediation : "";
        this.references = references != null ? references : "";
        this.httpMessage = httpMessage;
        this.activeProbe = activeProbe;
    }

    public String getTitle() {
        return title;
    }

    public IssueSeverity getSeverity() {
        return severity;
    }

    public IssueConfidence getConfidence() {
        return confidence;
    }

    public String getDescription() {
        return description;
    }

    public String getRemediation() {
        return remediation;
    }

    public String getReferences() {
        return references;
    }

    public HttpRequestResponse getHttpMessage() {
        return httpMessage;
    }

    public boolean isActiveProbe() {
        return activeProbe;
    }

    public AuditIssue toMontoyaAuditIssue() {
        if (httpMessage == null || httpMessage.request() == null) {
            return null;
        }
        return AuditIssue.auditIssue(
                title,
                description,
                remediation,
                httpMessage.request().url(),
                severity.toMontoyaSeverity(),
                confidence.toMontoyaConfidence(),
                references,
                remediation,
                severity.toMontoyaSeverity(),
                Collections.singletonList(httpMessage)
        );
    }
}
