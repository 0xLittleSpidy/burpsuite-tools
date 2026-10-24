// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.wordpressinspector.model.*;

import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Exporter for generating standard practitioner Markdown and JSON reports.
 * Excludes AI-ready report prompt formats as specified in project requirements.
 */
public class WordPressReportExporter_littlespidy {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static String generateMarkdown(WordPressTarget_littlespidy target) {
        StringBuilder sb = new StringBuilder();
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'").format(new Date());

        sb.append("# WordPress Security Assessment Report\n\n");
        sb.append("**Target URL**: ").append(target.getTargetUrl()).append("\n");
        sb.append("**Root Domain**: ").append(target.getRootDomain()).append("\n");
        sb.append("**Scan Date**: ").append(timestamp).append("\n");
        sb.append("**WordPress Version**: ").append(target.getDetectedVersion()).append("\n");
        sb.append("**Overall Status**: ").append(target.getScanStatus()).append("\n\n");
        sb.append("---\n\n");

        sb.append("## Executive Summary\n\n");
        sb.append("- Total Vulnerabilities: ").append(target.getTotalVulnerabilityCount()).append("\n");
        sb.append("- Core Vulnerabilities: ").append(target.getCoreVulnerabilities().size()).append("\n");
        sb.append("- Plugins Detected: ").append(target.getPlugins().size()).append("\n");
        sb.append("- Themes Detected: ").append(target.getThemes().size()).append("\n");
        sb.append("- Users Enumerated: ").append(target.getUsers().size()).append("\n");
        sb.append("- XML-RPC Status: ").append(target.getXmlRpcResult().getStatusSummary()).append("\n");
        sb.append("- REST API Exposure: ").append(target.getRestApiResult().isUsersExposed() ? "Users Exposed" : "Protected").append("\n\n");
        sb.append("---\n\n");

        // Core Vulnerabilities
        if (!target.getCoreVulnerabilities().isEmpty()) {
            sb.append("## WordPress Core Vulnerabilities\n\n");
            for (VulnerabilityEntry_littlespidy vuln : target.getCoreVulnerabilities()) {
                sb.append("### ").append(vuln.getTitle()).append("\n");
                sb.append("- **Type**: ").append(vuln.getVulnType()).append("\n");
                sb.append("- **Fixed In**: ").append(vuln.getFixedIn()).append("\n");
                sb.append("- **CVE(s)**: ").append(vuln.getPrimaryCve()).append("\n");
                if (!vuln.getReferences().isEmpty()) {
                    sb.append("- **References**:\n");
                    for (String ref : vuln.getReferences()) {
                        sb.append("  - ").append(ref).append("\n");
                    }
                }
                sb.append("\n");
            }
        }

        // Plugin Findings
        if (!target.getPlugins().isEmpty()) {
            sb.append("## Detected Plugins\n\n");
            for (PluginFinding_littlespidy plugin : target.getPlugins()) {
                sb.append("### Plugin: ").append(plugin.getSlug()).append("\n");
                sb.append("- **Detected Version**: ").append(plugin.getDetectedVersion()).append("\n");
                sb.append("- **Latest WP.org Version**: ").append(plugin.getLatestWpOrgVersion()).append("\n");
                sb.append("- **High-Risk Category**: ").append(plugin.isHighRisk() ? "Yes" : "No").append("\n");
                sb.append("- **Status**: ").append(plugin.getScanStatus()).append("\n");

                if (!plugin.getVulnerabilities().isEmpty()) {
                    sb.append("- **Known Vulnerabilities**:\n");
                    for (VulnerabilityEntry_littlespidy vuln : plugin.getVulnerabilities()) {
                        sb.append("  - **").append(vuln.getTitle()).append("** (Type: ")
                                .append(vuln.getVulnType()).append(", Fixed in: ").append(vuln.getFixedIn())
                                .append(", CVE: ").append(vuln.getPrimaryCve()).append(")\n");
                    }
                }
                sb.append("\n");
            }
        }

        // Theme Findings
        if (!target.getThemes().isEmpty()) {
            sb.append("## Detected Themes\n\n");
            for (ThemeFinding_littlespidy theme : target.getThemes()) {
                sb.append("### Theme: ").append(theme.getSlug()).append("\n");
                sb.append("- **Active**: ").append(theme.isActive() ? "Yes" : "No").append("\n");
                sb.append("- **Detected Version**: ").append(theme.getDetectedVersion()).append("\n");
                sb.append("- **Status**: ").append(theme.getScanStatus()).append("\n");
                if (!theme.getVulnerabilities().isEmpty()) {
                    sb.append("- **Known Vulnerabilities**:\n");
                    for (VulnerabilityEntry_littlespidy vuln : theme.getVulnerabilities()) {
                        sb.append("  - ").append(vuln.getTitle()).append(" (Fixed in: ").append(vuln.getFixedIn()).append(")\n");
                    }
                }
                sb.append("\n");
            }
        }

        // Users Enumeration
        if (!target.getUsers().isEmpty()) {
            sb.append("## Enumerated WordPress Accounts\n\n");
            sb.append("| ID | Username | Display Name | Slug | Vector |\n");
            sb.append("|---|---|---|---|---|\n");
            for (UserFinding_littlespidy u : target.getUsers()) {
                sb.append("| ").append(u.getId()).append(" | ")
                        .append(u.getUsername()).append(" | ")
                        .append(u.getDisplayName()).append(" | ")
                        .append(u.getSlug()).append(" | ")
                        .append(u.getVector()).append(" |\n");
            }
            sb.append("\n");
        }

        // Security Hardening
        if (!target.getHardeningFindings().isEmpty()) {
            sb.append("## Security Hardening Findings\n\n");
            for (String finding : target.getHardeningFindings()) {
                sb.append("- ").append(finding).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    public static String generateJson(WordPressTarget_littlespidy target) {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(new Date()));
        meta.put("target_url", target.getTargetUrl());
        meta.put("root_domain", target.getRootDomain());
        meta.put("scanner", "WordPress Inspector (littlespidy)");
        meta.put("wpscan_api_version", "v3");
        root.put("scan_metadata", meta);

        Map<String, Object> wpInfo = new LinkedHashMap<>();
        wpInfo.put("version", target.getDetectedVersion());
        wpInfo.put("status", target.getScanStatus());
        wpInfo.put("total_vulnerabilities", target.getTotalVulnerabilityCount());
        root.put("wordpress_info", wpInfo);

        root.put("core_vulnerabilities", target.getCoreVulnerabilities());
        root.put("plugins", target.getPlugins());
        root.put("themes", target.getThemes());
        root.put("users", target.getUsers());
        root.put("xmlrpc", target.getXmlRpcResult());
        root.put("rest_api", target.getRestApiResult());
        root.put("hardening", target.getHardeningFindings());

        return GSON.toJson(root);
    }
}
