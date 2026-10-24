// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Extension configuration model.
 */
public class ScanConfig_littlespidy {
    private String wpscanApiKey = "";
    private boolean liveScanEnabled = true;
    private boolean cache24hEnabled = true;
    private boolean smartPluginPriority = true;
    private boolean checkWpOrgUpdates = true;
    private boolean securityHardeningChecks = true;
    private int dailyApiCounter = 0;
    private String lastCounterResetDate = "";

    public ScanConfig_littlespidy() {
    }

    public String getWpscanApiKey() {
        return wpscanApiKey != null ? wpscanApiKey : "";
    }

    public void setWpscanApiKey(String wpscanApiKey) {
        this.wpscanApiKey = wpscanApiKey != null ? wpscanApiKey.trim() : "";
    }

    public boolean isLiveScanEnabled() {
        return liveScanEnabled;
    }

    public void setLiveScanEnabled(boolean liveScanEnabled) {
        this.liveScanEnabled = liveScanEnabled;
    }

    public boolean isCache24hEnabled() {
        return cache24hEnabled;
    }

    public void setCache24hEnabled(boolean cache24hEnabled) {
        this.cache24hEnabled = cache24hEnabled;
    }

    public boolean isSmartPluginPriority() {
        return smartPluginPriority;
    }

    public void setSmartPluginPriority(boolean smartPluginPriority) {
        this.smartPluginPriority = smartPluginPriority;
    }

    public boolean isCheckWpOrgUpdates() {
        return checkWpOrgUpdates;
    }

    public void setCheckWpOrgUpdates(boolean checkWpOrgUpdates) {
        this.checkWpOrgUpdates = checkWpOrgUpdates;
    }

    public boolean isSecurityHardeningChecks() {
        return securityHardeningChecks;
    }

    public void setSecurityHardeningChecks(boolean securityHardeningChecks) {
        this.securityHardeningChecks = securityHardeningChecks;
    }

    public int getDailyApiCounter() {
        return dailyApiCounter;
    }

    public void setDailyApiCounter(int dailyApiCounter) {
        this.dailyApiCounter = dailyApiCounter;
    }

    public synchronized void incrementDailyApiCounter() {
        this.dailyApiCounter++;
    }

    public String getLastCounterResetDate() {
        return lastCounterResetDate != null ? lastCounterResetDate : "";
    }

    public void setLastCounterResetDate(String lastCounterResetDate) {
        this.lastCounterResetDate = lastCounterResetDate;
    }
}
