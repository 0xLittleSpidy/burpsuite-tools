// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import com.littlespidy.quickhelper.model.ExtensionItem_littlespidy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Service that provides the catalog of official Burp Suite extensions published by littlespidy.
 */
public class ExtensionCatalogService_littlespidy {

    private static final String BASE_RELEASE_URL =
            "https://github.com/0xLittleSpidy/burpsuite-tools/releases/download/v1.0.0/";

    private final List<ExtensionItem_littlespidy> catalog;

    public ExtensionCatalogService_littlespidy() {
        this.catalog = new ArrayList<>();
        populateDefaultCatalog();
    }

    private void populateDefaultCatalog() {
        catalog.add(new ExtensionItem_littlespidy(
                "javascript-inspector",
                "JavaScript Inspector",
                "Recon & Secrets",
                "javascript-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "javascript-inspector-littlespidy-1.0.0.jar",
                "14.2 MB",
                "Client-side JavaScript analysis, sourcemap unpacker, endpoint and secret reconnaissance"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "cache-header-inspector",
                "Cache Header Inspector",
                "Protocol & Headers",
                "cache-header-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "cache-header-inspector-littlespidy-1.0.0.jar",
                "5.1 MB",
                "Passive CDN and cache header indexing and directive analysis"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "convert-post-to-get",
                "Convert POST to GET",
                "Auth & Session",
                "convert-post-to-get-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "convert-post-to-get-littlespidy-1.0.0.jar",
                "4.8 MB",
                "Request body to GET query converter for auth bypass testing"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "input-validation-fuzzer",
                "Input Validation Fuzzer",
                "Fuzzing & Injection",
                "input-validation-fuzzer-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "input-validation-fuzzer-littlespidy-1.0.0.jar",
                "6.2 MB",
                "Multi-point input validation and boundary fuzzer"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "response-inspector",
                "Response Inspector",
                "Recon & Secrets",
                "response-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "response-inspector-littlespidy-1.0.0.jar",
                "11.4 MB",
                "Response analyzer for passwords, strict SSNs, internal IPs, server paths, errors, and comments"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "jwt-comparator",
                "JWT Comparator",
                "Auth & Session",
                "jwt-comparator-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "jwt-comparator-littlespidy-1.0.0.jar",
                "7.9 MB",
                "Dynamic N-token JWT side-by-side comparator, claim diff matrix, timestamp translator"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "csp-inspector",
                "CSP Inspector",
                "Protocol & Headers",
                "csp-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "csp-inspector-littlespidy-1.0.0.jar",
                "4.9 MB",
                "Content Security Policy auditor, raw value and affected domain indexer"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "hsts-inspector",
                "HSTS Inspector",
                "Protocol & Headers",
                "hsts-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "hsts-inspector-littlespidy-1.0.0.jar",
                "4.6 MB",
                "HTTP Strict Transport Security auditor, raw value and affected domain indexer"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "upload-scanner",
                "Upload Scanner",
                "Fuzzing & Injection",
                "upload-scanner-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "upload-scanner-littlespidy-1.0.0.jar",
                "18.5 MB",
                "24-module file upload fuzzer, simplified 4-mode ReDownloader, Burp Collaborator OOB"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "session-inspector",
                "Session Inspector",
                "Auth & Session",
                "session-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "session-inspector-littlespidy-1.0.0.jar",
                "16.1 MB",
                "Automated session timeout and token expiration tester with staged milestone timers and cookie store"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "header-inspector",
                "Header Inspector",
                "Protocol & Headers",
                "header-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "header-inspector-littlespidy-1.0.0.jar",
                "12.8 MB",
                "Consolidated Protocol Suite: Header Collector, Method, Status, Cache, CSP, and HSTS"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "param-payload-injector",
                "Param Payload Injector",
                "Fuzzing & Injection",
                "param-payload-injector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "param-payload-injector-littlespidy-1.0.0.jar",
                "5.7 MB",
                "Parameter-attributed payload injector (XSS and Angular CSTI) with reflection monitoring"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "activescan-session-keeper",
                "Active Scan Session Keeper",
                "Automation",
                "activescan-session-keeper-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "activescan-session-keeper-littlespidy-1.0.0.jar",
                "6.9 MB",
                "Active scan session timeout interceptor that pauses scan threads on session expiry"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "gwtmap",
                "GWTMap",
                "Reverse Eng.",
                "gwtmap-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "gwtmap-littlespidy-1.0.0.jar",
                "8.3 MB",
                "GWT-RPC reverse engineering, permutation analysis, AST deserializer, and automated fuzzer"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "request-smuggling-inspector",
                "Request Smuggling Inspector",
                "Protocol & Headers",
                "request-smuggling-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "request-smuggling-inspector-littlespidy-1.0.0.jar",
                "5.4 MB",
                "HTTP request smuggling payload injector: CL.TE, TE.CL, TE.TE variants directly into Repeater"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "sso-inspector",
                "SSO Inspector",
                "Auth & Session",
                "sso-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "sso-inspector-littlespidy-1.0.0.jar",
                "9.2 MB",
                "Single Sign-On and OAuth 2.0 / OpenID Connect auditor with interactive OAuth workbench"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "api-inspector",
                "API Inspector",
                "API Testing",
                "api-inspector-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "api-inspector-littlespidy-1.0.0.jar",
                "8.7 MB",
                "REST API version discovery and representation prober with ResAPI Version Finder tab"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "ng-auth-analyzer",
                "ng-auth-analyzer",
                "Auth & Session",
                "ng-auth-analyzer_littlespidy-1.1.14.jar",
                BASE_RELEASE_URL + "ng-auth-analyzer_littlespidy-1.1.14.jar",
                "10.4 MB",
                "Automated authorization testing with Configuration, History, and Import tabs"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "ng-sqlmap",
                "ng-sqlmap",
                "SQL Injection",
                "ng-sqlmap-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "ng-sqlmap-littlespidy-1.0.0.jar",
                "11.1 MB",
                "Integrated SQLMap suite converting SQLiPy to Java with request sub-tabs and real-time streaming"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "quick-helper",
                "Quick Helper",
                "Productivity",
                "quick-helper-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "quick-helper-littlespidy-1.0.0.jar",
                "4.2 MB",
                "Quick helper actions for Burp Suite: copy unique domains and single-click extension downloader"
        ));

        catalog.add(new ExtensionItem_littlespidy(
                "js-sourcemap-explorer",
                "JS SourceMap Explorer",
                "Recon & Secrets",
                "js-sourcemap-explorer-littlespidy-1.0.0.jar",
                BASE_RELEASE_URL + "js-sourcemap-explorer-littlespidy-1.0.0.jar",
                "6.5 MB",
                "JavaScript source map explorer and reconstruction tool"
        ));
    }

    public List<ExtensionItem_littlespidy> getCatalog() {
        return Collections.unmodifiableList(catalog);
    }

    public int getExtensionCount() {
        return catalog.size();
    }
}
