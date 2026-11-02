// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

/**
 * Indicates where a parameter was detected.
 */
public enum ParameterSource_littlespidy {
    REQUEST_BODY("Request Body"),
    RESPONSE_BODY("Response Body"),
    BOTH("Both");

    private final String displayName;

    ParameterSource_littlespidy(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
