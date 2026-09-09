package com.littlespidy.uploadscanner.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Custom Montoya API ScanCheck for automated audit issue generation on file uploads.
 *
 * @author littlespidy
 */
public class UploadScanCheck implements ScanCheck {

    private final MontoyaApi api;

    public UploadScanCheck(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        // Active scan checks are executed when Burp Scanner audits an insertion point
        List<AuditIssue> issues = new ArrayList<>();
        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();

        if (!baseRequestResponse.hasResponse()) {
            return AuditResult.auditResult(issues);
        }

        String requestBody = baseRequestResponse.request().bodyToString();
        String responseBody = baseRequestResponse.response().bodyToString();

        // Passive check 1: Leaked direct upload storage path
        if (requestBody.contains("filename=\"") &&
                (responseBody.contains("/uploads/") || responseBody.contains("\\uploads\\") || responseBody.contains("s3.amazonaws.com"))) {
            issues.add(AuditIssue.auditIssue(
                    "Direct File Upload Path Exposure",
                    "The application reflected the direct destination storage directory or S3 bucket path of an uploaded file in the response.<br><br>" +
                            "Exposing direct upload directories may allow attackers to locate, access, and execute backdoored files or bypass access control restrictions.",
                    "Ensure direct storage paths are obscured or abstracted behind authenticated retrieval endpoints with strict access checks.",
                    baseRequestResponse.request().url(),
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,
                    "File upload vulnerabilities allow an attacker to upload dangerous files (e.g. PHP scripts or executable binaries) directly onto the web server.",
                    "Restrict uploaded file storage outside of the web root and disable server-side script execution in storage directories.",
                    AuditIssueSeverity.LOW,
                    baseRequestResponse
            ));
        }

        return AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.name().equals(existingIssue.name()) && newIssue.baseUrl().equals(existingIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
