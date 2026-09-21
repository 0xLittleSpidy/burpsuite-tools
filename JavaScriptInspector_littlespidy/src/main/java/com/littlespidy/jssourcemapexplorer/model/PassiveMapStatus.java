// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Result of passive source map detection (headers, trailing comments, inline base64).
 *
 * @author littlespidy
 */
public enum PassiveMapStatus {
    NOT_FOUND("Not Found"),
    COMMENT_FOUND("Found (Comment)"),
    HEADER_FOUND("Found (Header)"),
    INLINE_BASE64("Found (Inline Base64)");

    private final String label;

    PassiveMapStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public boolean isFound() {
        return this != NOT_FOUND;
    }
}
