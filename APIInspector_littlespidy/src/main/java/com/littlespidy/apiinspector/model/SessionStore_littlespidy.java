// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Stores session-specific HTTP headers to be applied to requests in API Inspector.
 * Users can paste raw HTTP headers (one per line) which strictly replace
 * matching headers on target requests.
 */
public class SessionStore_littlespidy {

    public static final String MODE_AUTH_REQUIRED_ONLY = "AUTH_REQUIRED_ONLY";
    public static final String MODE_ALL_REQUESTS = "ALL_REQUESTS";

    private boolean enabled;
    private String applyMode;
    private String rawHeaders;
    private Map<String, String> parsedHeaders;

    public SessionStore_littlespidy() {
        this.enabled = false;
        this.applyMode = MODE_AUTH_REQUIRED_ONLY;
        this.rawHeaders = "";
        this.parsedHeaders = new LinkedHashMap<>();
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

    public String getRawHeaders() {
        return rawHeaders != null ? rawHeaders : "";
    }

    public void setRawHeaders(String rawHeaders) {
        this.rawHeaders = rawHeaders != null ? rawHeaders : "";
        this.parsedHeaders = parseHeadersText(this.rawHeaders);
    }

    public Map<String, String> getParsedHeaders() {
        if (parsedHeaders == null) {
            parsedHeaders = parseHeadersText(rawHeaders);
        }
        return parsedHeaders;
    }

    public static Map<String, String> parseHeadersText(String text) {
        Map<String, String> map = new LinkedHashMap<>();
        if (text == null || text.isBlank()) {
            return map;
        }
        String[] lines = text.split("(\\r\\n|\\r|\\n)");
        for (String line : lines) {
            if (line == null) continue;
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            int colon = trimmed.indexOf(':');
            if (colon > 0) {
                String name = trimmed.substring(0, colon).trim();
                String value = trimmed.substring(colon + 1).trim();
                if (!name.isEmpty()) {
                    map.put(name, value);
                }
            }
        }
        return map;
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
        return applyToRequest(request);
    }

    public HttpRequest applyToRequest(HttpRequest request) {
        if (request == null || !enabled) {
            return request;
        }

        Map<String, String> headers = getParsedHeaders();
        if (headers == null || headers.isEmpty()) {
            return request;
        }

        HttpRequest modified = request;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            if (name != null && !name.isBlank()) {
                // Strict replace: withHeader replaces any existing header with the same name (including Cookie)
                modified = modified.withHeader(name.trim(), value != null ? value : "");
            }
        }

        return modified;
    }

    public String getStatusSummary() {
        if (!enabled) {
            return "Session Store: Inactive";
        }
        Map<String, String> headers = getParsedHeaders();
        int headerCount = headers != null ? headers.size() : 0;
        if (headerCount == 0) {
            return "Session Store: Active (No Headers)";
        }
        return "Session Store: Active (" + headerCount + " header" + (headerCount == 1 ? "" : "s") + ")";
    }

    // Deprecated compatibility helpers for older callers
    public String getBearerToken() {
        return getParsedHeaders().getOrDefault("Authorization", "");
    }

    public void setBearerToken(String bearerToken) {
        if (bearerToken != null && !bearerToken.isBlank()) {
            String val = bearerToken.trim();
            if (!val.toLowerCase().startsWith("bearer ")) {
                val = "Bearer " + val;
            }
            addHeader("Authorization", val);
        }
    }

    public Map<String, String> getCustomHeaders() {
        return getParsedHeaders();
    }

    public void setCustomHeaders(Map<String, String> headers) {
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                addHeader(e.getKey(), e.getValue());
            }
        }
    }

    public String getCookieName() {
        return "";
    }

    public void setCookieName(String cookieName) {}

    public String getCookieValue() {
        return "";
    }

    public void setCookieValue(String cookieValue) {}

    private void addHeader(String name, String value) {
        Map<String, String> current = new LinkedHashMap<>(getParsedHeaders());
        current.put(name, value);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : current.entrySet()) {
            sb.append(e.getKey()).append(": ").append(e.getValue()).append("\n");
        }
        setRawHeaders(sb.toString());
    }
}
