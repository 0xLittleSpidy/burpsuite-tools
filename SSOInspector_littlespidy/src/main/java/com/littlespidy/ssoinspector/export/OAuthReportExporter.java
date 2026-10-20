// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.export;

import com.littlespidy.ssoinspector.model.OAuthParam;
import com.littlespidy.ssoinspector.model.OAuthRequestEntry;
import com.littlespidy.ssoinspector.model.SSOAuditIssue;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

public class OAuthReportExporter {

    public static String exportToMarkdown(List<OAuthRequestEntry> entries) {
        StringBuilder sb = new StringBuilder();
        sb.append("# SSO Inspector (OAuth) Audit Report\n\n");
        sb.append("Total Captured OAuth Requests: ").append(entries.size()).append("\n\n");

        for (OAuthRequestEntry entry : entries) {
            sb.append("## Request #").append(entry.getId()).append(": ").append(entry.getMethod()).append(" ").append(entry.getUrl()).append("\n\n");
            sb.append("- **Timestamp**: ").append(entry.getTimestamp()).append("\n");
            sb.append("- **Host**: ").append(entry.getHost()).append("\n");
            sb.append("- **Flow Type**: ").append(entry.getFlowType().getDisplayName()).append("\n");
            sb.append("- **Highest Severity**: ").append(entry.getHighestSeverity().getLabel()).append("\n");
            sb.append("- **Issues Count**: ").append(entry.getIssuesCount()).append("\n\n");

            sb.append("### Detected OAuth Parameters\n\n");
            sb.append("| Parameter | Location | Value | Standard | Description |\n");
            sb.append("| :--- | :--- | :--- | :--- | :--- |\n");
            for (OAuthParam p : entry.getParameters()) {
                sb.append("| `").append(escapeMd(p.getName())).append("` | ")
                        .append(p.getLocation().getLabel()).append(" | `")
                        .append(escapeMd(p.getRawValue())).append("` | ")
                        .append(p.isStandard() ? "Yes" : "No").append(" | ")
                        .append(escapeMd(p.getDescription())).append(" |\n");
            }
            sb.append("\n");

            sb.append("### Security Findings\n\n");
            if (entry.getIssues().isEmpty()) {
                sb.append("No security vulnerabilities detected for this request.\n\n");
            } else {
                for (SSOAuditIssue issue : entry.getIssues()) {
                    sb.append("#### [").append(issue.getSeverity().getLabel().toUpperCase()).append("] ").append(issue.getTitle()).append("\n\n");
                    sb.append("- **Confidence**: ").append(issue.getConfidence().getLabel()).append("\n");
                    sb.append("- **Type**: ").append(issue.isActiveProbe() ? "Active Probe" : "Passive Audit").append("\n");
                    sb.append("- **Description**: ").append(issue.getDescription()).append("\n");
                    sb.append("- **Remediation**: ").append(issue.getRemediation()).append("\n");
                    if (!issue.getReferences().isBlank()) {
                        sb.append("- **References**: ").append(issue.getReferences()).append("\n");
                    }
                    sb.append("\n");
                }
            }
            sb.append("---\n\n");
        }

        return sb.toString();
    }

    public static String exportToJson(List<OAuthRequestEntry> entries) {
        JSONArray rootArr = new JSONArray();

        for (OAuthRequestEntry entry : entries) {
            JSONObject entryObj = new JSONObject();
            entryObj.put("id", entry.getId());
            entryObj.put("timestamp", entry.getTimestamp());
            entryObj.put("method", entry.getMethod());
            entryObj.put("url", entry.getUrl());
            entryObj.put("host", entry.getHost());
            entryObj.put("path", entry.getPath());
            entryObj.put("flowType", entry.getFlowType().getDisplayName());
            entryObj.put("highestSeverity", entry.getHighestSeverity().getLabel());
            entryObj.put("issuesCount", entry.getIssuesCount());

            JSONArray paramsArr = new JSONArray();
            for (OAuthParam p : entry.getParameters()) {
                JSONObject pObj = new JSONObject();
                pObj.put("name", p.getName());
                pObj.put("location", p.getLocation().getLabel());
                pObj.put("rawValue", p.getRawValue());
                pObj.put("decodedValue", p.getDecodedValue());
                pObj.put("isStandard", p.isStandard());
                pObj.put("description", p.getDescription());
                paramsArr.put(pObj);
            }
            entryObj.put("parameters", paramsArr);

            JSONArray issuesArr = new JSONArray();
            for (SSOAuditIssue issue : entry.getIssues()) {
                JSONObject iObj = new JSONObject();
                iObj.put("title", issue.getTitle());
                iObj.put("severity", issue.getSeverity().getLabel());
                iObj.put("confidence", issue.getConfidence().getLabel());
                iObj.put("isActiveProbe", issue.isActiveProbe());
                iObj.put("description", issue.getDescription());
                iObj.put("remediation", issue.getRemediation());
                iObj.put("references", issue.getReferences());
                issuesArr.put(iObj);
            }
            entryObj.put("issues", issuesArr);

            rootArr.put(entryObj);
        }

        return rootArr.toString(2);
    }

    private static String escapeMd(String text) {
        if (text == null) return "";
        return text.replace("|", "\\|").replace("\n", " ").replace("\r", "");
    }
}
