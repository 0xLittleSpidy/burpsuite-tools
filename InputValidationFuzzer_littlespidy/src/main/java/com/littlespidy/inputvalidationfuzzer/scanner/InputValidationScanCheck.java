package com.littlespidy.inputvalidationfuzzer.scanner;

import com.littlespidy.inputvalidationfuzzer.model.FuzzPayload;
import com.littlespidy.inputvalidationfuzzer.model.FuzzerConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
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
import java.util.Set;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Montoya ScanCheck implementation of the Input Validation Fuzzer.
 * Automatically runs during Burp active scans per insertion point.
 *
 * @author littlespidy
 */
public class InputValidationScanCheck implements ScanCheck {
    private final MontoyaApi api;
    private final FuzzerConfig config;

    private static final Set<String> ALLOWED_INSERTION_POINT_TYPES = Set.of(
        "PARAMETER_URL",
        "PARAMETER_BODY",
        "PARAMETER_COOKIE",
        "PARAMETER_JSON",
        "PARAMETER_XML",
        "PARAMETER_XML_ATTRIBUTE",
        "PARAMETER_MULTIPART_ATTRIBUTE",
        "PARAMETER_NAME_URL",
        "PARAMETER_NAME_BODY"
    );

    public InputValidationScanCheck(MontoyaApi api, FuzzerConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        if (insertionPoint == null || !baseRequestResponse.hasResponse()) {
            return AuditResult.auditResult();
        }

        String typeName = insertionPoint.type().name();
        if (!ALLOWED_INSERTION_POINT_TYPES.contains(typeName)) {
            return AuditResult.auditResult();
        }

        if ("PARAMETER_COOKIE".equals(typeName) && !config.isFuzzCookieParams()) {
            return AuditResult.auditResult();
        }

        int baseStatus = baseRequestResponse.response().statusCode();
        int baseBodyLen = baseRequestResponse.response().body().length();
        List<AuditIssue> issues = new ArrayList<>();

        for (FuzzPayload payload : config.getPayloads()) {
            HttpRequestResponse rr = api.http().sendRequest(
                insertionPoint.buildHttpRequestWithPayload(
                    ByteArray.byteArray(payload.value())
                )
            );

            if (!rr.hasResponse()) {
                continue;
            }

            var resp = rr.response();
            int respStatus = resp.statusCode();
            int respBodyLen = resp.body().length();
            String respBody = resp.bodyToString().toLowerCase();

            boolean serverError = (respStatus >= 500);
            boolean statusChanged = (respStatus != baseStatus && respStatus >= 400);

            boolean errorFound = false;
            String matchedError = "";
            for (String sig : config.getErrorSignatures()) {
                if (respBody.contains(sig.toLowerCase())) {
                    errorFound = true;
                    matchedError = sig;
                    break;
                }
            }

            boolean payloadReflected = !payload.value().isEmpty()
                && respBody.contains(payload.value().toLowerCase());

            boolean sizeDiff = baseBodyLen > 0
                && ((double) respBodyLen / baseBodyLen) * 100 > config.getSizeDiffPercent();

            if (serverError || errorFound) {
                AuditIssueSeverity severity = serverError ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
                AuditIssueConfidence confidence = errorFound ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE;

                String detail = "<p><b>Test:</b> " + payload.name() + "</p>"
                    + "<p>" + payload.detail() + "</p>"
                    + "<p><b>Evidence:</b></p><ul>"
                    + (serverError ? "<li>Server returned HTTP <b>" + respStatus + "</b> (baseline was " + baseStatus + ")</li>" : "")
                    + (errorFound ? "<li>Error signature found: <code>" + api.utilities().htmlUtils().encode(matchedError) + "</code></li>" : "")
                    + "</ul>";

                issues.add(AuditIssue.auditIssue(
                    "Input Validation Failure: " + payload.name(),
                    detail,
                    "Implement server-side input validation and sanitization. "
                        + "Ensure error pages do not leak internal details (stack traces, SQL queries, file paths).",
                    rr.request().url(),
                    severity,
                    confidence,
                    "<p>Improper input validation can lead to injection attacks, denial of service, "
                        + "or information disclosure through verbose error messages.</p>",
                    "<p>Validate and sanitize all user inputs on the server side. "
                        + "Use parameterized queries for database operations. "
                        + "Implement generic error pages that do not reveal internal state.</p>",
                    severity,
                    rr
                ));
            } else if (payloadReflected) {
                issues.add(AuditIssue.auditIssue(
                    "Input Reflection Detected: " + payload.name(),
                    "<p><b>Test:</b> " + payload.name() + "</p>"
                        + "<p>The injected payload was reflected in the response body without encoding, "
                        + "which may indicate a potential injection or XSS vulnerability.</p>"
                        + "<p>" + payload.detail() + "</p>",
                    "Encode or sanitize user input before reflecting it in responses. "
                        + "Apply context-appropriate output encoding (HTML, JS, URL).",
                    rr.request().url(),
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.TENTATIVE,
                    "<p>When user input is reflected without encoding, it can enable "
                        + "cross-site scripting (XSS) or other injection attacks.</p>",
                    "<p>Apply context-appropriate output encoding before reflecting user input. "
                        + "Use Content-Security-Policy headers as a defense-in-depth measure.</p>",
                    AuditIssueSeverity.MEDIUM,
                    rr
                ));
            } else if (statusChanged || sizeDiff) {
                issues.add(AuditIssue.auditIssue(
                    "Anomalous Response to Fuzz Input: " + payload.name(),
                    "<p><b>Test:</b> " + payload.name() + "</p>"
                        + "<p>" + payload.detail() + "</p>"
                        + "<p><b>Anomaly detected:</b></p><ul>"
                        + (statusChanged ? "<li>Status code changed from <b>" + baseStatus + "</b> to <b>" + respStatus + "</b></li>" : "")
                        + (sizeDiff ? "<li>Response body size changed significantly (<b>" + baseBodyLen + "</b> → <b>" + respBodyLen + "</b> bytes)</li>" : "")
                        + "</ul>",
                    "Review server-side handling of unexpected input values.",
                    rr.request().url(),
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.TENTATIVE,
                    "<p>Significant changes in response status or size when injecting unexpected values "
                        + "may indicate improper input handling that warrants manual investigation.</p>",
                    "",
                    AuditIssueSeverity.INFORMATION,
                    rr
                ));
            }
        }

        return issues.isEmpty() ? AuditResult.auditResult() : AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return AuditResult.auditResult();
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name())
            && newIssue.baseUrl().equals(existingIssue.baseUrl())
            ? ConsolidationAction.KEEP_EXISTING
            : ConsolidationAction.KEEP_BOTH;
    }
}
