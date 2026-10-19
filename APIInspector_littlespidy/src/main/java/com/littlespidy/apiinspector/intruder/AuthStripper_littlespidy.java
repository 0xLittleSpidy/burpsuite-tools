// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.intruder;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Utility for stripping authentication tokens, headers, and cookies from HTTP requests
 * to generate unauthenticated test variants while preserving unrelated request data.
 */
public class AuthStripper_littlespidy {

    private static final Set<String> AUTH_HEADER_NAMES = Set.of(
            "authorization",
            "proxy-authorization",
            "x-auth-token",
            "x-access-token",
            "x-api-key",
            "api-key",
            "apikey",
            "token",
            "auth-token",
            "x-user-id",
            "x-user-token",
            "jwt",
            "x-jwt-assertion",
            "bearer"
    );

    private static final Pattern AUTH_COOKIE_PATTERN = Pattern.compile(
            "^(?:.*_)?(?:session|sessionid|phpsessid|jsessionid|aspsessionid|sid|token|jwt|auth|auth_token|authorization|access_token|refresh_token|connect\\.sid|remember_me|logged_in)(?:_.*)?$",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Creates an unauthenticated copy of the request by stripping auth headers
     * and auth cookies while preserving all unrelated request properties and non-auth cookies.
     */
    public static HttpRequest stripAuthentication(HttpRequest originalRequest) {
        if (originalRequest == null) {
            return null;
        }

        HttpRequest modified = originalRequest;

        // 1. Remove Authentication Headers
        List<HttpHeader> headers = modified.headers();
        if (headers != null) {
            for (HttpHeader h : headers) {
                String nameLower = h.name().toLowerCase(Locale.ROOT);
                if (AUTH_HEADER_NAMES.contains(nameLower)) {
                    modified = modified.withRemovedHeader(h.name());
                }
            }
        }

        // 2. Filter Authentication Cookies from Cookie Header
        String cookieVal = modified.headerValue("Cookie");
        if (cookieVal != null && !cookieVal.isBlank()) {
            String[] parts = cookieVal.split(";");
            List<String> retainedCookies = new ArrayList<>();

            for (String part : parts) {
                String trimmed = part.trim();
                if (trimmed.isEmpty()) continue;

                int eqIdx = trimmed.indexOf('=');
                String cookieName = (eqIdx != -1) ? trimmed.substring(0, eqIdx).trim() : trimmed;

                if (!isAuthCookie(cookieName)) {
                    retainedCookies.add(trimmed);
                }
            }

            if (!retainedCookies.isEmpty()) {
                modified = modified.withHeader("Cookie", String.join("; ", retainedCookies));
            } else {
                modified = modified.withRemovedHeader("Cookie");
            }
        }

        return modified;
    }

    public static boolean isAuthHeader(String headerName) {
        if (headerName == null) return false;
        return AUTH_HEADER_NAMES.contains(headerName.trim().toLowerCase(Locale.ROOT));
    }

    public static boolean isAuthCookie(String cookieName) {
        if (cookieName == null) return false;
        return AUTH_COOKIE_PATTERN.matcher(cookieName.trim()).matches();
    }
}
