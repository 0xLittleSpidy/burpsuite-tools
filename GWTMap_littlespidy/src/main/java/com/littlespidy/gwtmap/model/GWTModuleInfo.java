// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Encapsulates GWT application module metadata discovered from bootstrap
 * ({name}.nocache.js) or permutation ({hex}.cache.js) files.
 *
 * @author littlespidy
 */
public class GWTModuleInfo {

    private String targetUrl = "Unknown";
    private String gwtVersion = "Unknown";
    private String activePermutation = "Unknown";
    private List<String> allPermutations = new ArrayList<>();
    private String contentType = "text/x-gwt-rpc; charset=utf-8";
    private String baseUrl = "http://127.0.0.1/stub/";
    private String rpcVersion = "7";
    private String rpcFlags = "0";
    private List<String> deferredFragments = new ArrayList<>();

    public GWTModuleInfo() {}

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getGwtVersion() {
        return gwtVersion;
    }

    public void setGwtVersion(String gwtVersion) {
        this.gwtVersion = gwtVersion;
    }

    public String getActivePermutation() {
        return activePermutation;
    }

    public void setActivePermutation(String activePermutation) {
        this.activePermutation = activePermutation;
    }

    public List<String> getAllPermutations() {
        return Collections.unmodifiableList(allPermutations);
    }

    public void addPermutation(String permutation) {
        if (permutation != null && !permutation.isBlank() && !allPermutations.contains(permutation)) {
            allPermutations.add(permutation);
        }
    }

    public void setAllPermutations(List<String> permutations) {
        allPermutations.clear();
        if (permutations != null) {
            for (String p : permutations) {
                addPermutation(p);
            }
        }
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getRpcVersion() {
        return rpcVersion;
    }

    public void setRpcVersion(String rpcVersion) {
        this.rpcVersion = rpcVersion;
    }

    public String getRpcFlags() {
        return rpcFlags;
    }

    public void setRpcFlags(String rpcFlags) {
        this.rpcFlags = rpcFlags;
    }

    public List<String> getDeferredFragments() {
        return Collections.unmodifiableList(deferredFragments);
    }

    public void addDeferredFragment(String fragmentUrl) {
        if (fragmentUrl != null && !deferredFragments.contains(fragmentUrl)) {
            deferredFragments.add(fragmentUrl);
        }
    }

    public void clearDeferredFragments() {
        deferredFragments.clear();
    }
}
