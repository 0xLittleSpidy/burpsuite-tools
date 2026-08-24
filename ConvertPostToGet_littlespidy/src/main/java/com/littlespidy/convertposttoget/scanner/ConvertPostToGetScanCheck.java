package com.littlespidy.convertposttoget.scanner;

import com.littlespidy.convertposttoget.engine.PostToGetConverter;
import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Active ScanCheck that converts audited POST requests to GET and flags
 * successful method interchanges, CSRF risks, or authorization bypasses.
 *
 * @author littlespidy
 */
public class ConvertPostToGetScanCheck implements ScanCheck {
    private final MontoyaApi api;
    private final ConvertPostToGetConfig config;
    private final PostToGetConverter converter;

    public ConvertPostToGetScanCheck(MontoyaApi api, ConvertPostToGetConfig config) {
        this.api = api;
        this.config = config;
        this.converter = new PostToGetConverter(api, config);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        if (!baseRequestResponse.hasResponse()) {
            return AuditResult.auditResult();
        }

        HttpRequest originalReq = baseRequestResponse.request();
        if (!originalReq.method().equalsIgnoreCase("POST")) {
            return AuditResult.auditResult();
        }

        HttpRequest getRequest = converter.convertPostToGet(originalReq, Collections.emptyList());
        HttpRequestResponse getRr = api.http().sendRequest(getRequest);

        if (!getRr.hasResponse()) {
            return AuditResult.auditResult();
        }

        HttpResponse getResp = getRr.response();
        int baseStatus = baseRequestResponse.response().statusCode();
        int getStatus = getResp.statusCode();

        List<AuditIssue> issues = new ArrayList<>();

        boolean isBypass = (baseStatus == 401 || baseStatus == 403) && (getStatus == 200 || getStatus == 302);
        boolean isMethodPermitted = (getStatus >= 200 && getStatus < 300);

        if (isBypass) {
            issues.add(AuditIssue.auditIssue(
                "POST to GET Authorization / WAF Bypass",
                "<p>The original <b>POST</b> request was blocked with HTTP <b>" + baseStatus + "</b>, "
                    + "but converting the request to a <b>GET</b> with query parameters succeeded with HTTP <b>" + getStatus + "</b>.</p>",
                "Ensure authorization rules, WAF policies, and CSRF validations apply equally regardless of HTTP method.",
                getRequest.url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "<p>Inconsistent method enforcement can allow attackers to bypass access controls or WAF rules by switching HTTP verbs.</p>",
                "<p>Enforce strict verb-specific routing and apply authentication middleware uniformly across all HTTP methods.</p>",
                AuditIssueSeverity.HIGH,
                getRr
            ));
        } else if (isMethodPermitted) {
            issues.add(AuditIssue.auditIssue(
                "POST Request Accepted via GET (Potential CSRF / State Mutation)",
                "<p>The application accepted a converted <b>GET</b> request containing body parameters moved to the URL query string (HTTP <b>" + getStatus + "</b>).</p>",
                "Restrict state-changing endpoints to POST/PUT/DELETE methods only. Explicitly reject GET requests for state mutations.",
                getRequest.url(),
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.TENTATIVE,
                "<p>If a state-changing POST endpoint accepts GET requests, it may be vulnerable to Cross-Site Request Forgery (CSRF) via simple &lt;img&gt; tags or &lt;a&gt; links.</p>",
                "<p>Configure the route handler to strictly validate and enforce the POST method.</p>",
                AuditIssueSeverity.MEDIUM,
                getRr
            ));
        }

        return issues.isEmpty() ? AuditResult.auditResult() : AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return AuditResult.auditResult();
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name()) && newIssue.baseUrl().equals(existingIssue.baseUrl())
            ? ConsolidationAction.KEEP_EXISTING
            : ConsolidationAction.KEEP_BOTH;
    }
}
