// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Encapsulates the execution result of replaying a single HTTP request with a specific JWT token or unauthenticated.
 */
public class TokenAttackResult {

    public enum StatusType {
        ACCEPTED,      // 2xx Success
        REJECTED,      // 401 Unauthorized / 403 Forbidden
        REDIRECT,      // 3xx Redirection
        CLIENT_ERROR,  // 4xx other client errors
        SERVER_ERROR,  // 5xx Server Error
        FAILED         // Connection timeout / network error
    }

    private final int slotIndex;
    private final String tokenName;
    private final int statusCode;
    private final String statusReason;
    private final int responseLength;
    private final long responseTimeMs;
    private final HttpRequest request;
    private final HttpResponse response;
    private final StatusType statusType;
    private final String error;

    public TokenAttackResult(int slotIndex, String tokenName, int statusCode, String statusReason,
                             int responseLength, long responseTimeMs,
                             HttpRequest request, HttpResponse response, String error) {
        this.slotIndex = slotIndex;
        this.tokenName = tokenName != null ? tokenName : "Token " + slotIndex;
        this.statusCode = statusCode;
        this.statusReason = statusReason != null ? statusReason : "";
        this.responseLength = responseLength;
        this.responseTimeMs = responseTimeMs;
        this.request = request;
        this.response = response;
        this.error = error;

        if (error != null && !error.isEmpty()) {
            this.statusType = StatusType.FAILED;
        } else if (statusCode >= 200 && statusCode < 300) {
            this.statusType = StatusType.ACCEPTED;
        } else if (statusCode == 401 || statusCode == 403) {
            this.statusType = StatusType.REJECTED;
        } else if (statusCode >= 300 && statusCode < 400) {
            this.statusType = StatusType.REDIRECT;
        } else if (statusCode >= 500 && statusCode < 600) {
            this.statusType = StatusType.SERVER_ERROR;
        } else {
            this.statusType = StatusType.CLIENT_ERROR;
        }
    }

    public static TokenAttackResult failed(int slotIndex, String tokenName, HttpRequest request, String error) {
        return new TokenAttackResult(slotIndex, tokenName, 0, "Failed", 0, 0, request, null, error);
    }

    public int getSlotIndex() {
        return slotIndex;
    }

    public String getTokenName() {
        return tokenName;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getStatusReason() {
        return statusReason;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    public StatusType getStatusType() {
        return statusType;
    }

    public String getError() {
        return error;
    }

    public boolean isAccepted() {
        return statusType == StatusType.ACCEPTED;
    }

    public boolean isRejected() {
        return statusType == StatusType.REJECTED;
    }

    public String getDisplayText() {
        if (statusType == StatusType.FAILED) {
            return "Failed: " + (error != null ? error : "Network Error");
        }
        String lenStr = formatLength(responseLength);
        if (statusReason.isEmpty()) {
            return statusCode + " (" + lenStr + ")";
        }
        return statusCode + " " + statusReason + " (" + lenStr + ")";
    }

    private static String formatLength(int bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        }
    }
}
