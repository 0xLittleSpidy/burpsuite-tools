// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class CommonConfig_littlespidy {

    public static final String DEFAULT_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

    public static final String DEFAULT_CDX_TEMPLATE =
            "https://web.archive.org/cdx/search/cdx?url={DOMAIN}&output=txt&fl=original&collapse=urlkey";

    public static final List<String> DEFAULT_SIGNATURES = List.of(
            "Index of /",
            "Directory Listing for",
            "<title>Index of",
            "Parent Directory</a>",
            "Last modified</a>",
            "Name</a>",
            "Size</a>",
            "Description</a>"
    );

    private String userAgent = DEFAULT_USER_AGENT;
    private String cdxUrlTemplate = DEFAULT_CDX_TEMPLATE;
    private int cdxRetries = 3;
    private int cdxRetryDelaySec = 5;
    private boolean testBothHttpHttps = true;
    private boolean honorBurpProxy = true;

    private final List<String> signatures = new CopyOnWriteArrayList<>(DEFAULT_SIGNATURES);
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    public CommonConfig_littlespidy() {
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        if (userAgent != null && !userAgent.isBlank()) {
            this.userAgent = userAgent.trim();
            notifyListeners();
        }
    }

    public String getCdxUrlTemplate() {
        return cdxUrlTemplate;
    }

    public void setCdxUrlTemplate(String cdxUrlTemplate) {
        if (cdxUrlTemplate != null && !cdxUrlTemplate.isBlank()) {
            this.cdxUrlTemplate = cdxUrlTemplate.trim();
            notifyListeners();
        }
    }

    public int getCdxRetries() {
        return cdxRetries;
    }

    public void setCdxRetries(int cdxRetries) {
        this.cdxRetries = Math.max(1, Math.min(10, cdxRetries));
        notifyListeners();
    }

    public int getCdxRetryDelaySec() {
        return cdxRetryDelaySec;
    }

    public void setCdxRetryDelaySec(int cdxRetryDelaySec) {
        this.cdxRetryDelaySec = Math.max(1, Math.min(60, cdxRetryDelaySec));
        notifyListeners();
    }

    public boolean isTestBothHttpHttps() {
        return testBothHttpHttps;
    }

    public void setTestBothHttpHttps(boolean testBothHttpHttps) {
        this.testBothHttpHttps = testBothHttpHttps;
        notifyListeners();
    }

    public boolean isHonorBurpProxy() {
        return honorBurpProxy;
    }

    public void setHonorBurpProxy(boolean honorBurpProxy) {
        this.honorBurpProxy = honorBurpProxy;
        notifyListeners();
    }

    public List<String> getSignatures() {
        return Collections.unmodifiableList(signatures);
    }

    public void addSignature(String signature) {
        if (signature != null && !signature.isBlank() && !signatures.contains(signature.trim())) {
            signatures.add(signature.trim());
            notifyListeners();
        }
    }

    public void removeSignature(String signature) {
        if (signatures.remove(signature)) {
            notifyListeners();
        }
    }

    public void resetSignatures() {
        signatures.clear();
        signatures.addAll(DEFAULT_SIGNATURES);
        notifyListeners();
    }

    public void setSignatures(List<String> newSignatures) {
        signatures.clear();
        if (newSignatures != null) {
            for (String sig : newSignatures) {
                if (sig != null && !sig.isBlank() && !signatures.contains(sig.trim())) {
                    signatures.add(sig.trim());
                }
            }
        }
        notifyListeners();
    }

    public String findMatchingSignature(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }
        for (String sig : signatures) {
            if (responseBody.contains(sig)) {
                return sig;
            }
        }
        return null;
    }

    public void addChangeListener(Runnable listener) {
        if (listener != null) {
            changeListeners.add(listener);
        }
    }

    public void removeChangeListener(Runnable listener) {
        changeListeners.remove(listener);
    }

    private void notifyListeners() {
        for (Runnable listener : changeListeners) {
            try {
                listener.run();
            } catch (Exception ignored) {
            }
        }
    }
}
