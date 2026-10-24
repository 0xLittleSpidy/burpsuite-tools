// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.session;

import com.littlespidy.wayback.config.CommonConfig_littlespidy;
import com.littlespidy.wayback.model.DirectoryFinding_littlespidy;
import com.littlespidy.wayback.model.DiscoveredPath_littlespidy;
import com.littlespidy.wayback.model.DiscoveredSubdomain_littlespidy;
import com.littlespidy.wayback.model.DomainScanConfig_littlespidy;

import java.util.ArrayList;
import java.util.List;

public class SessionData_littlespidy {

    private String savedTimestamp;
    private CommonConfigData commonConfig;
    private List<DomainSessionState_littlespidy> domains = new ArrayList<>();

    public static class CommonConfigData {
        public String userAgent;
        public String cdxUrlTemplate;
        public int cdxRetries;
        public int cdxRetryDelaySec;
        public boolean testBothHttpHttps;
        public boolean honorBurpProxy;
        public List<String> signatures;
    }

    public static class DomainSessionState_littlespidy {
        public String domain;
        public DomainScanConfig_littlespidy scanConfig;
        public List<DiscoveredPath_littlespidy> paths = new ArrayList<>();
        public List<DiscoveredSubdomain_littlespidy> subdomains = new ArrayList<>();
        public List<DirectoryFinding_littlespidy> findings = new ArrayList<>();
    }

    public String getSavedTimestamp() {
        return savedTimestamp;
    }

    public void setSavedTimestamp(String savedTimestamp) {
        this.savedTimestamp = savedTimestamp;
    }

    public CommonConfigData getCommonConfig() {
        return commonConfig;
    }

    public void setCommonConfig(CommonConfigData commonConfig) {
        this.commonConfig = commonConfig;
    }

    public List<DomainSessionState_littlespidy> getDomains() {
        return domains;
    }

    public void setDomains(List<DomainSessionState_littlespidy> domains) {
        this.domains = domains != null ? domains : new ArrayList<>();
    }
}
