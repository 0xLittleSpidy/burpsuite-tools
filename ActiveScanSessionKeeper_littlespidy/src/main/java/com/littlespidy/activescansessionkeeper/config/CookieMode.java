// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.config;

/**
 * Mode determining how session credentials are replaced in intercepted HTTP requests.
 *
 * @author littlespidy
 */
public enum CookieMode {
    /** Replace only specific named cookies (e.g. JSESSIONID, token) within the Cookie header. */
    NAMED_COOKIES("Named Cookies"),

    /** Replace the entire Cookie header value with user-provided raw header string. */
    FULL_COOKIE_HEADER("Full Cookie Header"),

    /** Replace or inject Authorization: Bearer <token> header. */
    AUTHORIZATION_BEARER("Authorization Bearer Header");

    private final String displayName;

    CookieMode(String displayName) {
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
