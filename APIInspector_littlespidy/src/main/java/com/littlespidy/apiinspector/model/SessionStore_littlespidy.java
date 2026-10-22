// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Stores session-specific authentication information such as tokens,
 * custom headers, and cookies to be applied to requests in API Inspector.
 */
public class SessionStore_littlespidy {

    public static final String MODE_AUTH_REQUIRED_ONLY = "AUTH_REQUIRED_ONLY";
    public static final String MODE_ALL_REQUESTS = "ALL_REQUESTS";

    private boolean enabled;
    private String applyMode;
    private String bearerToken;
    private Map<String, String> customHeaders;
    private String cookieName;
    private String cookieValue;

    public SessionStore_littlespidy() {
        this.enabled = false;
        this.applyMode = MODE_AUTH_REQUIRED_ONLY;
        this.bearerToken = "";
        this.customHeaders = new LinkedHashMap<>();
        this.cookieName = "";
        this.cookieValue = "";
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getApplyMode() {
        return applyMode != null ? applyMode : MODE_AUTH_REQUIRED_ONLY;
    }

    public void setApplyMode(String applyMode) {
        this.applyMode = applyMode != null ? applyMode : MODE_AUTH_REQUIRED_ONLY;
    }

    public String getBearerToken() {
        return bearerToken != null ? bearerToken : "";
    }

    public void setBearerToken(String bearerToken) {
        this.bearerToken = bearerToken != null ? bearerToken : "";
    }

    public Map<String, String> getCustomHeaders() {
        if (customHeaders == null) {
            customHeaders = new LinkedHashMap<>();
        }
        return customHeaders;
    }

    public void setCustomHeaders(Map<String, String> headers) {
        this.customHeaders = headers != null ? new LinkedHashMap<>(headers) : new LinkedHashMap<>();
    }

    public String getCookieName() {
        return cookieName != null ? cookieName : "";
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName != null ? cookieName : "";
    }

    public String getCookieValue() {
        return cookieValue != null ? cookieValue : "";
    }

    public void setCookieValue(String cookieValue) {
        this.cookieValue = cookieValue != null ? cookieValue : "";
    }

    public boolean appliesTo(DiscoveredEndpoint_littlespidy endpoint) {
        if (!enabled) {
            return false;
        }
        if (MODE_ALL_REQUESTS.equals(applyMode)) {
            return true;
        }
        return endpoint != null && endpoint.isRequiresAuth();
    }

    public HttpRequest applyToRequest(HttpRequest request, DiscoveredEndpoint_littlespidy endpoint) {
        if (request == null || !appliesTo(endpoint)) {
            return request;
        }

        HttpRequest modified = request;

        // 1. Bearer Token
        if (bearerToken != null && !bearerToken.isBlank()) {
            String token = bearerToken.trim();
            if (!token.toLowerCase().startsWith("bearer ")) {
                token = "Bearer " + token;
            }
            modified = modified.withHeader("Authorization", token);
        }

        // 2. Custom Headers
        if (customHeaders != null) {
            for (Map.Entry<String, String> entry : customHeaders.entrySet()) {
                String k = entry.getKey();
                String v = entry.getValue();
                if (k != null && !k.isBlank()) {
                    modified = modified.withHeader(k.trim(), v != null ? v.trim() : "");
                }
            }
        }

        // 3. Cookie
        if (cookieName != null && !cookieName.isBlank() && cookieValue != null && !cookieValue.isBlank()) {
            String cookiePair = cookieName.trim() + "=" + cookieValue.trim();
            if (modified.hasHeader("Cookie")) {
                String existing = modified.headerValue("Cookie");
                if (existing != null && !existing.isBlank()) {
                    if (!existing.contains(cookieName.trim() + "=")) {
                        modified = modified.withHeader("Cookie", existing.trim() + "; " + cookiePair);
                    }
                } else {
                    modified = modified.withHeader("Cookie", cookiePair);
                }
            } else {
                modified = modified.withHeader("Cookie", cookiePair);
            }
        }

        return modified;
    }

    public String getStatusSummary() {
        if (!enabled) {
            return "Session Store: Inactive";
        }
        int headerCount = customHeaders != null ? customHeaders.size() : 0;
        boolean hasToken = bearerToken != null && !bearerToken.isBlank();
        boolean hasCookie = cookieName != null && !cookieName.isBlank() && cookieValue != null && !cookieValue.isBlank();

        StringBuilder sb = new StringBuilder("Session Store: Active (");
        boolean first = true;
        if (hasToken) {
            sb.append("Token");
            first = false;
        }
        if (headerCount > 0) {
            if (!first) sb.append(", ");
            sb.append(headerCount).append(" Header(s)");
            first = false;
        }
        if (hasCookie) {
            if (!first) sb.append(", ");
            sb.append("Cookie");
            first = false;
        }
        if (first) {
            sb.append("No Credentials Set");
        }
        sb.append(")");
        return sb.toString();
    }
}
