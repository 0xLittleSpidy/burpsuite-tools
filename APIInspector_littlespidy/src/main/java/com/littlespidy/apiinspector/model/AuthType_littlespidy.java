// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

/**
 * Supported authentication mechanisms for API collections and endpoints.
 */
public enum AuthType_littlespidy {
    BEARER_TOKEN("Bearer Token"),
    API_KEY("API Key"),
    BASIC_AUTH("Basic Authentication"),
    COOKIE("Cookie Authentication"),
    CUSTOM_HEADER("Custom Header");

    private final String displayName;

    AuthType_littlespidy(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
