// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

/**
 * Finding categories representing the functional tabs in Response Inspector.
 */
public enum FindingCategory {
    PASSWORD("Passwords", "Analyzes configured passwords leaked in responses"),
    PII_NETWORK_PATH("PII, Network & Paths", "Detects SSNs, RFC1918 internal IPs, and OS filesystem paths"),
    ERROR("Errors & Exceptions", "Detects server errors, stack traces, and database leaks"),
    SECRET("Secrets", "Detects cloud API keys, auth tokens, private keys, and JWTs"),
    COMMENT("Comments", "Extracts developer comments from HTTP responses (TODO, credentials, debug hints)");

    private final String displayName;
    private final String description;

    FindingCategory(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
