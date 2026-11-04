// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.model;

public class DomainScanConfig_littlespidy {

    private String targetDomain;
    private boolean autoDiscoverSubdomains = true;
    private boolean inScopeOnly = false;
    private boolean addToSiteMap = true;
    private int threads = 10;
    private int delayMs = 50;
    private int timeoutSec = 10;
    private boolean enablePassiveRecon = true;
    private boolean enableParetoWordlist = true;
    private boolean enableJsMining = true;
    private boolean enableArchiveDiffing = true;
    private boolean enableWafAutoThrottle = true;

    public DomainScanConfig_littlespidy() {
        this.targetDomain = "";
    }

    public DomainScanConfig_littlespidy(String targetDomain) {
        this.targetDomain = targetDomain != null ? targetDomain.trim() : "";
    }

    public boolean isEnablePassiveRecon() {
        return enablePassiveRecon;
    }

    public void setEnablePassiveRecon(boolean enablePassiveRecon) {
        this.enablePassiveRecon = enablePassiveRecon;
    }

    public boolean isEnableParetoWordlist() {
        return enableParetoWordlist;
    }

    public void setEnableParetoWordlist(boolean enableParetoWordlist) {
        this.enableParetoWordlist = enableParetoWordlist;
    }

    public boolean isEnableJsMining() {
        return enableJsMining;
    }

    public void setEnableJsMining(boolean enableJsMining) {
        this.enableJsMining = enableJsMining;
    }

    public boolean isEnableArchiveDiffing() {
        return enableArchiveDiffing;
    }

    public void setEnableArchiveDiffing(boolean enableArchiveDiffing) {
        this.enableArchiveDiffing = enableArchiveDiffing;
    }

    public boolean isEnableWafAutoThrottle() {
        return enableWafAutoThrottle;
    }

    public void setEnableWafAutoThrottle(boolean enableWafAutoThrottle) {
        this.enableWafAutoThrottle = enableWafAutoThrottle;
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
