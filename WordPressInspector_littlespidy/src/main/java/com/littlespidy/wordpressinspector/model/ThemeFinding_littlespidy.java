// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Model for a detected WordPress theme.
 */
public class ThemeFinding_littlespidy {
    private String slug;
    private String detectedVersion;
    private boolean isActive;
    private String scanStatus = "Not Scanned";
    private List<VulnerabilityEntry_littlespidy> vulnerabilities = new ArrayList<>();
    private String detectionPath;

    public ThemeFinding_littlespidy() {
    }

    public ThemeFinding_littlespidy(String slug) {
        this.slug = slug;
        this.isActive = true;
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

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
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

    public String getDetectionPath() {
        return detectionPath != null ? detectionPath : "";
    }

    public void setDetectionPath(String detectionPath) {
        this.detectionPath = detectionPath;
    }
}
