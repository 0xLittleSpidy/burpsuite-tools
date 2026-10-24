// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Model for a detected WordPress plugin.
 */
public class PluginFinding_littlespidy {
    private String slug;
    private String detectedVersion;
    private String latestWpOrgVersion;
    private boolean isHighRisk;
    private String scanStatus = "Not Scanned"; // Not Scanned, Scanned, Cached, Vulnerable, Clean, Error
    private List<VulnerabilityEntry_littlespidy> vulnerabilities = new ArrayList<>();
    private String detectionSource = "HTTP Traffic";

    public PluginFinding_littlespidy() {
    }

    public PluginFinding_littlespidy(String slug) {
        this.slug = slug;
    }

    public String getSlug() {
        return slug != null ? slug : "";
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getDetectedVersion() {
        return detectedVersion != null && !detectedVersion.isEmpty() ? detectedVersion : "Unknown";
    }

    public void setDetectedVersion(String detectedVersion) {
        this.detectedVersion = detectedVersion;
    }

    public String getLatestWpOrgVersion() {
        return latestWpOrgVersion != null && !latestWpOrgVersion.isEmpty() ? latestWpOrgVersion : "Unknown";
    }

    public void setLatestWpOrgVersion(String latestWpOrgVersion) {
        this.latestWpOrgVersion = latestWpOrgVersion;
    }

    public boolean isHighRisk() {
        return isHighRisk;
    }

    public void setHighRisk(boolean highRisk) {
        isHighRisk = highRisk;
    }

    public String getScanStatus() {
        if (!vulnerabilities.isEmpty()) {
            return "Vulnerable";
        }
        return scanStatus;
    }

    public void setScanStatus(String scanStatus) {
        this.scanStatus = scanStatus;
    }

    public List<VulnerabilityEntry_littlespidy> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<VulnerabilityEntry_littlespidy> vulnerabilities) {
        this.vulnerabilities = vulnerabilities != null ? vulnerabilities : new ArrayList<>();
        if (!this.vulnerabilities.isEmpty()) {
            this.scanStatus = "Vulnerable";
        }
    }

    public int getVulnerabilityCount() {
        return vulnerabilities != null ? vulnerabilities.size() : 0;
    }

    public String getDetectionSource() {
        return detectionSource;
    }

    public void setDetectionSource(String detectionSource) {
        this.detectionSource = detectionSource;
    }
}
