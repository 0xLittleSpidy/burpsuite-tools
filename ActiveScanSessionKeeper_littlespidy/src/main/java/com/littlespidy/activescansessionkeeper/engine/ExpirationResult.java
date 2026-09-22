// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.engine;

/**
 * Result of inspecting an HTTP response for session expiration indicators.
 *
 * @author littlespidy
 */
public class ExpirationResult {

    private final boolean expired;
    private final String reason;
    private final String details;

    public ExpirationResult(boolean expired, String reason, String details) {
        this.expired = expired;
        this.reason = reason;
        this.details = details;
    }

    public static ExpirationResult active(String details) {
        return new ExpirationResult(false, "Active", details);
    }

    public static ExpirationResult expired(String reason, String details) {
        return new ExpirationResult(true, reason, details);
    }

    public boolean isExpired() {
        return expired;
    }

    public String getReason() {
        return reason;
    }

    public String getDetails() {
        return details;
    }
}
