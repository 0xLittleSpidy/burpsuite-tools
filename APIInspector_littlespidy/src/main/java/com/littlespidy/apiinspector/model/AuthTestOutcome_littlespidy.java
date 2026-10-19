// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

/**
 * Objective classification outcomes for API authentication test executions.
 */
public enum AuthTestOutcome_littlespidy {
    AUTHENTICATED_ONLY("AUTHENTICATED_ONLY", "Endpoint properly requires authentication (Authenticated 2xx, Unauthenticated 401/403)"),
    UNAUTHENTICATED_ACCESSIBLE("UNAUTHENTICATED_ACCESSIBLE", "Endpoint accessible without authentication (Authenticated 2xx, Unauthenticated 2xx)"),
    AUTH_REJECTED("AUTH_REJECTED", "Configured authentication rejected or unauthorized (Authenticated 401/403)"),
    SUCCESS("SUCCESS", "Request completed successfully (2xx status)"),
    CLIENT_ERROR("CLIENT_ERROR", "Client error encountered (4xx status, e.g. 400, 404, 422)"),
    SERVER_ERROR("SERVER_ERROR", "Target server error encountered (5xx status)"),
    NETWORK_ERROR("NETWORK_ERROR", "Network failure, connection error, or timeout");

    private final String code;
    private final String description;

    AuthTestOutcome_littlespidy(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return code;
    }
}
