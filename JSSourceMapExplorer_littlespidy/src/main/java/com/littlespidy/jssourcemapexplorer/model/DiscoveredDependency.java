// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents an NPM or internal package dependency extracted from package.json
 * structures or /node_modules/ paths, including its active verification status
 * against public NPM registry for Dependency Confusion detection.
 *
 * @author littlespidy
 */
public class DiscoveredDependency {
    private final String sourceLocation;
    private final String sourceType;
    private final String packageName;
    private final String version;
    private final String dependencyType; // "package.json dependencies", "node_modules path"
    private volatile String status;      // "Unverified", "Checking...", "Registered (OK)", "VULNERABLE: 404 Unclaimed", "Org Not Found"
    private volatile String verificationDetail;
    private final int line;
    private final String contextSnippet;

    public DiscoveredDependency(
        String sourceLocation,
        String sourceType,
        String packageName,
        String version,
        String dependencyType,
        String status,
        String verificationDetail,
        int line,
        String contextSnippet
    ) {
        this.sourceLocation = sourceLocation;
        this.sourceType = sourceType;
        this.packageName = packageName;
        this.version = (version != null && !version.trim().isEmpty()) ? version : "-";
        this.dependencyType = dependencyType;
        this.status = (status != null) ? status : "Unverified";
        this.verificationDetail = (verificationDetail != null) ? verificationDetail : "-";
        this.line = line;
        this.contextSnippet = contextSnippet;
    }

    public String sourceLocation() { return sourceLocation; }
    public String sourceType() { return sourceType; }
    public String packageName() { return packageName; }
    public String version() { return version; }
    public String dependencyType() { return dependencyType; }
    public String status() { return status; }
    public String verificationDetail() { return verificationDetail; }
    public int line() { return line; }
    public String contextSnippet() { return contextSnippet; }

    public void setStatus(String status, String detail) {
        this.status = status;
        this.verificationDetail = detail;
    }
}
