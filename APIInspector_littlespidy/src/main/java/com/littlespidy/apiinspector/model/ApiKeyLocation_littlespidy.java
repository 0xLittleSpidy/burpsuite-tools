// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

/**
 * Injection location for API Key authentication.
 */
public enum ApiKeyLocation_littlespidy {
    HEADER("Header"),
    QUERY_PARAM("Query Parameter");

    private final String displayName;

    ApiKeyLocation_littlespidy(String displayName) {
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
