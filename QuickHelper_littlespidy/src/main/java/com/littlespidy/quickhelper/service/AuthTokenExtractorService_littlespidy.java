// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.quickhelper.model.AuthItem_littlespidy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Service to parse and extract authentication tokens, headers, and cookies from HTTP requests.
 */
public class AuthTokenExtractorService_littlespidy {

    private static final String[] KNOWN_AUTH_HEADERS = {
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "apikey",
            "token",
            "x-csrf-token",
            "x-xsrf-token"
    };

    /**
     * Extracts all identified authentication tokens, cookies, and relevant auth headers from a request.
     *
     * @param request the HTTP request to inspect
     * @return list of extracted items
     */
    public List<AuthItem_littlespidy> extractAll(HttpRequest request) {
        if (request == null) {
            return Collections.emptyList();
        }

        List<AuthItem_littlespidy> items = new ArrayList<>();
        List<HttpHeader> headers;
        try {
            headers = request.headers();
        } catch (Exception e) {
            return Collections.emptyList();
        }

        if (headers == null || headers.isEmpty()) {
            return Collections.emptyList();
        }

        String authHeaderValue = null;
        String cookieHeaderValue = null;

        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();
            if (name == null || value == null) {
                continue;
            }

            String lowerName = name.trim().toLowerCase();

            if (lowerName.equals("authorization")) {
                authHeaderValue = value.trim();
            } else if (lowerName.equals("cookie")) {
                cookieHeaderValue = value.trim();
            }
        }

        // Process Authorization header
        if (authHeaderValue != null && !authHeaderValue.isEmpty()) {
            if (authHeaderValue.regionMatches(true, 0, "Bearer ", 0, 7)) {
                String tokenOnly = authHeaderValue.substring(7).trim();
                if (!tokenOnly.isEmpty()) {
                    items.add(new AuthItem_littlespidy("Bearer Token", "Bearer (raw token)", tokenOnly));
                }
            }

            items.add(new AuthItem_littlespidy("Auth Header", "Authorization", "Authorization: " + authHeaderValue));
        }

        // Process Cookie header
        if (cookieHeaderValue != null && !cookieHeaderValue.isEmpty()) {
            items.add(new AuthItem_littlespidy("Cookie Header", "Cookie (complete)", cookieHeaderValue));

            // Parse individual cookies
            String[] cookiePairs = cookieHeaderValue.split(";");
            for (String pair : cookiePairs) {
                String trimmed = pair.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int eqIdx = trimmed.indexOf('=');
                if (eqIdx > 0) {
                    String cName = trimmed.substring(0, eqIdx).trim();
                    String cVal = trimmed.substring(eqIdx + 1).trim();
                    if (!cName.isEmpty()) {
                        items.add(new AuthItem_littlespidy("Cookie", cName, cVal));
                    }
                } else if (!trimmed.isEmpty()) {
                    items.add(new AuthItem_littlespidy("Cookie", trimmed, ""));
                }
            }
        }

        // Process known custom auth headers
        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();
            if (name == null || value == null) {
                continue;
            }

            String lowerName = name.trim().toLowerCase();
            for (String known : KNOWN_AUTH_HEADERS) {
                if (lowerName.equals(known)) {
                    String trimmedValue = value.trim();
                    if (!trimmedValue.isEmpty()) {
                        items.add(new AuthItem_littlespidy("Custom Header", name.trim(), trimmedValue));
                    }
                    break;
                }
            }
        }

        return items;
    }

    /**
     * Extracts pure Bearer token without scheme prefix if present.
     */
    public String extractBearerToken(HttpRequest request) {
        String authValue = extractAuthHeaderValue(request);
        if (authValue != null && authValue.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return authValue.substring(7).trim();
        }
        return null;
    }

    /**
     * Extracts the raw Authorization header value (without 'Authorization: ' prefix).
     */
    public String extractAuthHeaderValue(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            for (HttpHeader header : request.headers()) {
                if (header.name() != null && header.name().trim().equalsIgnoreCase("authorization")) {
                    String val = header.value();
                    return val != null ? val.trim() : null;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Extracts the complete Authorization header including 'Authorization: ' prefix.
     */
    public String extractFullAuthHeader(HttpRequest request) {
        String val = extractAuthHeaderValue(request);
        if (val != null && !val.isEmpty()) {
            return "Authorization: " + val;
        }
        return null;
    }

    /**
     * Extracts the Authorization header with 'Authorization: ' prefix.
     */
    public String extractAuthHeader(HttpRequest request) {
        return extractFullAuthHeader(request);
    }

    /**
     * Extracts the complete raw Cookie header value if present.
     */
    public String extractCookieHeader(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            for (HttpHeader header : request.headers()) {
                if (header.name() != null && header.name().trim().equalsIgnoreCase("cookie")) {
                    String val = header.value();
                    return val != null ? val.trim() : null;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}
