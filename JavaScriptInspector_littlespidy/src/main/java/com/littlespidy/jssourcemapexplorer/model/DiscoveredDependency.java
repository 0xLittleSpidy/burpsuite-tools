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
    private final int startOffset;
    private final int endOffset;
    private final String contextSnippet;
    private volatile String classification = "Not Classified";

    public DiscoveredDependency(
        String sourceLocation,
        String sourceType,
        String packageName,
        String version,
        String dependencyType,
        String status,
        String verificationDetail,
        int line,
        int startOffset,
        int endOffset,
        String contextSnippet,
        String classification
    ) {
        this.sourceLocation = sourceLocation;
        this.sourceType = sourceType;
        this.packageName = packageName;
        this.version = (version != null && !version.trim().isEmpty()) ? version : "-";
        this.dependencyType = dependencyType;
        this.status = (status != null) ? status : "Unverified";
        this.verificationDetail = (verificationDetail != null) ? verificationDetail : "-";
        this.line = line;
        this.startOffset = startOffset;
        this.endOffset = endOffset;
        this.contextSnippet = contextSnippet;
        this.classification = (classification != null && !classification.isBlank()) ? classification : "Not Classified";
    }

    public DiscoveredDependency(
        String sourceLocation,
        String sourceType,
        String packageName,
        String version,
        String dependencyType,
        String status,
        String verificationDetail,
        int line,
        int startOffset,
        int endOffset,
        String contextSnippet
    ) {
        this(sourceLocation, sourceType, packageName, version, dependencyType, status, verificationDetail, line, startOffset, endOffset, contextSnippet, "Not Classified");
    }

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
        this(sourceLocation, sourceType, packageName, version, dependencyType, status, verificationDetail, line, 0, 0, contextSnippet);
    }

    public String sourceLocation() { return sourceLocation; }
    public String sourceType() { return sourceType; }
    public String packageName() { return packageName; }
    public String version() { return version; }
    public String dependencyType() { return dependencyType; }
    public String status() { return status; }
    public String verificationDetail() { return verificationDetail; }
    public int line() { return line; }
    public int startOffset() { return startOffset; }
    public int endOffset() { return endOffset; }
    public String contextSnippet() { return contextSnippet; }
    public String getClassification() {
        return (classification != null && !classification.isBlank()) ? classification : "Not Classified";
    }
    public void setClassification(String classification) {
        this.classification = (classification != null && !classification.isBlank()) ? classification : "Not Classified";
    }

    public DiscoveredDependency withClassification(String newClass) {
        return new DiscoveredDependency(
            sourceLocation, sourceType, packageName, version, dependencyType, status, verificationDetail, line, startOffset, endOffset, contextSnippet, newClass
        );
    }

    public void setStatus(String status, String detail) {
        this.status = status;
        this.verificationDetail = detail;
    }
}
