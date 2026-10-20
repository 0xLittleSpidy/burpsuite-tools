// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.littlespidy.ssoinspector.model.*;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class SSOScanCheck implements ScanCheck {

    private final MontoyaApi api;
    private final OAuthActiveScanEngine activeScanEngine;

    public SSOScanCheck(MontoyaApi api, OAuthActiveScanEngine activeScanEngine) {
        this.api = api;
        this.activeScanEngine = activeScanEngine;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        if (baseRequestResponse == null || baseRequestResponse.request() == null) {
            return AuditResult.auditResult();
        }

        // Only trigger on relevant insertion points or once per request to avoid huge duplicated fuzzing
        String pointName = auditInsertionPoint != null ? auditInsertionPoint.name().toLowerCase() : "";
        if (!pointName.equals("redirect_uri") && !pointName.equals("response_type") && !pointName.equals("code") && !pointName.equals("state") && !pointName.isEmpty()) {
            return AuditResult.auditResult();
        }

        List<OAuthParam> params = OAuthParameterParser.parseParameters(baseRequestResponse.request());
        OAuthFlowType flow = OAuthFlowClassifier.classify(baseRequestResponse.request().path(), params);

        if (flow == OAuthFlowType.UNKNOWN_OR_CUSTOM && params.isEmpty()) {
            return AuditResult.auditResult();
        }

        OAuthRequestEntry tempEntry = new OAuthRequestEntry(0, baseRequestResponse);
        tempEntry.setParameters(params);
        tempEntry.setFlowType(flow);

        List<SSOAuditIssue> detected = activeScanEngine.runAttacks(
                tempEntry,
                EnumSet.allOf(OAuthActiveScanEngine.AttackType.class),
                null,
                null
        );

        List<AuditIssue> montoyaIssues = new ArrayList<>();
        for (SSOAuditIssue issue : detected) {
            AuditIssue mi = issue.toMontoyaAuditIssue();
            if (mi != null) {
                montoyaIssues.add(mi);
            }
        }

        return montoyaIssues.isEmpty() ? AuditResult.auditResult() : AuditResult.auditResult(montoyaIssues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse == null || baseRequestResponse.request() == null) {
            return AuditResult.auditResult();
        }

        List<OAuthParam> params = OAuthParameterParser.parseParameters(baseRequestResponse.request());
        OAuthFlowType flow = OAuthFlowClassifier.classify(baseRequestResponse.request().path(), params);

        if (flow == OAuthFlowType.UNKNOWN_OR_CUSTOM && params.isEmpty()) {
            return AuditResult.auditResult();
        }

        List<SSOAuditIssue> detected = OAuthPassiveAuditEngine.audit(baseRequestResponse, params, flow);
        List<AuditIssue> montoyaIssues = new ArrayList<>();
        for (SSOAuditIssue issue : detected) {
            AuditIssue mi = issue.toMontoyaAuditIssue();
            if (mi != null) {
                montoyaIssues.add(mi);
            }
        }

        return montoyaIssues.isEmpty() ? AuditResult.auditResult() : AuditResult.auditResult(montoyaIssues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.name().equalsIgnoreCase(existingIssue.name()) && newIssue.baseUrl().equalsIgnoreCase(existingIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
