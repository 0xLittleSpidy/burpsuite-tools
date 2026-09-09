package com.littlespidy.uploadscanner.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Configuration holder for the ReDownloader engine.
 *
 * @author littlespidy
 */
public class ReDownloaderConfig {
    public static final String MARKER_FILENAME = "${FILENAME}";
    public static final String MARKER_FILENAME_NO_EXT = "${FILENAME_NO_EXT}";
    public static final String MARKER_ORIG_EXT = "${ORIG_EXT}";
    public static final String MARKER_RANDOMIZE = "${RANDOMIZE}";

    private boolean enabled = true;
    private String preflightUrl = "";
    private String startMarker = "";
    private String endMarker = "";
    private String staticUrl = "";
    private String urlPrefix = "";
    private String urlSuffix = "";
    private boolean replaceBackslash = true;

    public ReDownloaderConfig() {
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getPreflightUrl() {
        return preflightUrl != null ? preflightUrl : "";
    }

    public void setPreflightUrl(String preflightUrl) {
        this.preflightUrl = preflightUrl;
    }

    public String getStartMarker() {
        return startMarker != null ? startMarker : "";
    }

    public void setStartMarker(String startMarker) {
        this.startMarker = startMarker;
    }

    public String getEndMarker() {
        return endMarker != null ? endMarker : "";
    }

    public void setEndMarker(String endMarker) {
        this.endMarker = endMarker;
    }

    public String getStaticUrl() {
        return staticUrl != null ? staticUrl : "";
    }

    public void setStaticUrl(String staticUrl) {
        this.staticUrl = staticUrl;
    }

    public String getUrlPrefix() {
        return urlPrefix != null ? urlPrefix : "";
    }

    public void setUrlPrefix(String urlPrefix) {
        this.urlPrefix = urlPrefix;
    }

    public String getUrlSuffix() {
        return urlSuffix != null ? urlSuffix : "";
    }

    public void setUrlSuffix(String urlSuffix) {
        this.urlSuffix = urlSuffix;
    }

    public boolean isReplaceBackslash() {
        return replaceBackslash;
    }

    public void setReplaceBackslash(boolean replaceBackslash) {
        this.replaceBackslash = replaceBackslash;
    }

    public boolean isConfigured() {
        return (!getStartMarker().isEmpty() && !getEndMarker().isEmpty()) || !getStaticUrl().isEmpty();
    }
}
