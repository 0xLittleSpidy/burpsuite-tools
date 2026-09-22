// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.model;

/**
 * Indicates whether a cookie was observed in an HTTP Request (Cookie header),
 * an HTTP Response (Set-Cookie header), or both.
 *
 * @author littlespidy
 */
public enum CookieSource {
    REQUEST("Request"),
    RESPONSE("Response"),
    BOTH("Both");

    private final String displayName;

    CookieSource(String displayName) {
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
