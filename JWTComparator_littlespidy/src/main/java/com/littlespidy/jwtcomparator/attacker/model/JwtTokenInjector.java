// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.model;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Mutates an HttpRequest by injecting a specific JWT token or stripping authentication.
 */
public class JwtTokenInjector {

    private static final Pattern JWT_PATTERN =
            Pattern.compile("\\beyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_\\-\\./+=]*\\b");

    private static final List<String> CUSTOM_AUTH_HEADERS = List.of(
            "x-access-token", "x-auth-token", "token", "jwt", "x-jwt-assertion", "x-id-token"
    );

    /**
     * Injects a JWT into the given request.
     * Looks for Authorization header, cookies containing JWTs, or custom headers.
     * If no existing token is found, defaults to adding Authorization: Bearer <token>.
     */
    public static HttpRequest injectToken(HttpRequest request, String newToken) {
        if (request == null || newToken == null || newToken.trim().isEmpty()) {
            return request;
        }
        String cleanToken = newToken.trim();
        if (cleanToken.regionMatches(true, 0, "bearer ", 0, 7)) {
            cleanToken = cleanToken.substring(7).trim();
        }

        HttpRequest mutated = request;
        boolean replaced = false;

        // 1. Check Authorization header
        if (mutated.hasHeader("Authorization")) {
            String authVal = mutated.headerValue("Authorization");
            if (authVal != null && (authVal.toLowerCase().startsWith("bearer ") || JWT_PATTERN.matcher(authVal).find())) {
                mutated = mutated.withUpdatedHeader("Authorization", "Bearer " + cleanToken);
                replaced = true;
            }
        }

        // 2. Check Custom Auth Headers
        for (HttpHeader h : mutated.headers()) {
            String nameLower = h.name().toLowerCase();
            if (CUSTOM_AUTH_HEADERS.contains(nameLower)) {
                mutated = mutated.withUpdatedHeader(h.name(), cleanToken);
                replaced = true;
            }
        }

        // 3. Check Cookie headers
        if (mutated.hasHeader("Cookie")) {
            String cookieHeader = mutated.headerValue("Cookie");
            if (cookieHeader != null && JWT_PATTERN.matcher(cookieHeader).find()) {
                String updatedCookies = replaceJwtInCookies(cookieHeader, cleanToken);
                mutated = mutated.withUpdatedHeader("Cookie", updatedCookies);
                replaced = true;
            }
        }

        // 4. If not replaced in Authorization, custom headers, or cookies, append Authorization: Bearer
        if (!replaced) {
            if (mutated.hasHeader("Authorization")) {
                mutated = mutated.withUpdatedHeader("Authorization", "Bearer " + cleanToken);
            } else {
                mutated = mutated.withAddedHeader("Authorization", "Bearer " + cleanToken);
            }
        }

        return mutated;
    }

    /**
     * Strips authentication tokens from the given request for unauthenticated baseline testing.
     */
    public static HttpRequest stripAuth(HttpRequest request) {
        if (request == null) {
            return null;
        }

        HttpRequest mutated = request;

        // Remove Authorization header
        if (mutated.hasHeader("Authorization")) {
            mutated = mutated.withRemovedHeader("Authorization");
        }

        // Remove custom auth headers
        for (String custom : CUSTOM_AUTH_HEADERS) {
            for (HttpHeader h : mutated.headers()) {
                if (h.name().equalsIgnoreCase(custom)) {
                    mutated = mutated.withRemovedHeader(h.name());
                }
            }
        }

        // Remove JWT tokens from Cookie header
        if (mutated.hasHeader("Cookie")) {
            String cookieHeader = mutated.headerValue("Cookie");
            if (cookieHeader != null && JWT_PATTERN.matcher(cookieHeader).find()) {
                String cleanedCookies = removeJwtFromCookies(cookieHeader);
                if (cleanedCookies.trim().isEmpty()) {
                    mutated = mutated.withRemovedHeader("Cookie");
                } else {
                    mutated = mutated.withUpdatedHeader("Cookie", cleanedCookies);
                }
            }
        }

        return mutated;
    }

    private static String replaceJwtInCookies(String cookieHeader, String newToken) {
        String[] pairs = cookieHeader.split(";\\s*");
        List<String> result = new ArrayList<>();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String name = pair.substring(0, eq).trim();
                String val = pair.substring(eq + 1).trim();
                String nameLower = name.toLowerCase();
                if (JWT_PATTERN.matcher(val).find() || nameLower.equals("jwt") || nameLower.equals("token") || nameLower.equals("access_token") || nameLower.equals("id_token") || nameLower.equals("auth_token")) {
                    result.add(name + "=" + newToken);
                } else {
                    result.add(pair);
                }
            } else {
                result.add(pair);
            }
        }
        return String.join("; ", result);
    }

    private static String removeJwtFromCookies(String cookieHeader) {
        String[] pairs = cookieHeader.split(";\\s*");
        List<String> result = new ArrayList<>();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String name = pair.substring(0, eq).trim();
                String val = pair.substring(eq + 1).trim();
                String nameLower = name.toLowerCase();
                if (JWT_PATTERN.matcher(val).find() || nameLower.equals("jwt") || nameLower.equals("token") || nameLower.equals("access_token") || nameLower.equals("id_token") || nameLower.equals("auth_token")) {
                    // Strip this cookie
                    continue;
                }
            }
            result.add(pair);
        }
        return String.join("; ", result);
    }
}
