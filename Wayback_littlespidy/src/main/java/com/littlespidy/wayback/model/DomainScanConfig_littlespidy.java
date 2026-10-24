// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.model;

public class DomainScanConfig_littlespidy {

    private String targetDomain;
    private boolean autoDiscoverSubdomains = true;
    private boolean inScopeOnly = false;
    private boolean addToSiteMap = true;
    private int threads = 10;
    private int delayMs = 50;
    private int timeoutSec = 10;

    public DomainScanConfig_littlespidy() {
        this.targetDomain = "";
    }

    public DomainScanConfig_littlespidy(String targetDomain) {
        this.targetDomain = targetDomain != null ? targetDomain.trim() : "";
    }

    public String getTargetDomain() {
        return targetDomain;
    }

    public void setTargetDomain(String targetDomain) {
        this.targetDomain = targetDomain != null ? targetDomain.trim() : "";
    }

    public boolean isAutoDiscoverSubdomains() {
        return autoDiscoverSubdomains;
    }

    public void setAutoDiscoverSubdomains(boolean autoDiscoverSubdomains) {
        this.autoDiscoverSubdomains = autoDiscoverSubdomains;
    }

    public boolean isInScopeOnly() {
        return inScopeOnly;
    }

    public void setInScopeOnly(boolean inScopeOnly) {
        this.inScopeOnly = inScopeOnly;
    }

    public boolean isAddToSiteMap() {
        return addToSiteMap;
    }

    public void setAddToSiteMap(boolean addToSiteMap) {
        this.addToSiteMap = addToSiteMap;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = Math.max(1, Math.min(50, threads));
    }

    public int getDelayMs() {
        return delayMs;
    }

    public void setDelayMs(int delayMs) {
        this.delayMs = Math.max(0, Math.min(5000, delayMs));
    }

    public int getTimeoutSec() {
        return timeoutSec;
    }

    public void setTimeoutSec(int timeoutSec) {
        this.timeoutSec = Math.max(2, Math.min(60, timeoutSec));
    }
}
