// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Status of Source Map (.map) detection and exposure for a JavaScript file.
 *
 * @author littlespidy
 */
public enum MapExposureStatus {
    NONE("No .map Found"),
    COMMENT_DETECTED("Comment Detected"),
    HEADER_DETECTED("Header Detected"),
    INLINE_BASE64("Inline Base64 Map"),
    ACTIVE_PROBE_FOUND("Probe Found (.map 200)"),
    PROBE_FAILED("Probe Not Found (404)"),
    UNPACKED("Unpacked");

    private final String displayLabel;

    MapExposureStatus(String displayLabel) {
        this.displayLabel = displayLabel;
    }

    public String getDisplayLabel() {
        return displayLabel;
    }

    public boolean isExposed() {
        return this == COMMENT_DETECTED
            || this == HEADER_DETECTED
            || this == INLINE_BASE64
            || this == ACTIVE_PROBE_FOUND
            || this == UNPACKED;
    }
}
