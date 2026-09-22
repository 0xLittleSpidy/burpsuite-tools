// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.engine;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Inspection engine that evaluates HTTP responses from active scanner requests against
 * configurable multi-factor expiration criteria.
 *
 * @author littlespidy
 */
public class ExpirationDetector {

    private final SessionKeeperConfig config;

    public ExpirationDetector(SessionKeeperConfig config) {
        this.config = config;
    }

    /**
     * Inspects an HTTP response for signs of session expiration.
     *
     * @param response the received HTTP response
     * @return ExpirationResult indicating if session has expired and the rationale
     */
    public ExpirationResult evaluate(HttpResponse response) {
        if (response == null) {
            return ExpirationResult.active("Null response received");
        }

        int statusCode = response.statusCode();

        // ── 1. Status Code Criteria ──
        if (config.isCheckStatusCodes()) {
            Set<Integer> codes = config.parseStatusCodes();
            if (codes.contains(statusCode)) {
                return ExpirationResult.expired(
                        "Status Code " + statusCode,
                        "Server returned HTTP " + statusCode + ", matching configured session expiration status codes."
                );
            }
        }

        // ── 2. Redirect to Login / Authentication Endpoint ──
        if (config.isCheckRedirects() && statusCode >= 300 && statusCode < 400) {
            String location = response.headerValue("Location");
            if (location != null && !location.isEmpty()) {
                String patternStr = config.getRedirectLocationRegex();
                try {
                    Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
                    if (pattern.matcher(location).matches() || pattern.matcher(location).find()) {
                        return ExpirationResult.expired(
                                "Redirect (" + statusCode + ") to " + location,
                                "Probe was redirected (" + statusCode + ") to authentication/login endpoint: " + location
                        );
                    }
                } catch (Exception e) {
                    if (location.toLowerCase(Locale.ROOT).contains("login") ||
                        location.toLowerCase(Locale.ROOT).contains("signin") ||
                        location.toLowerCase(Locale.ROOT).contains("auth")) {
                        return ExpirationResult.expired(
                                "Redirect (" + statusCode + ") to " + location,
                                "Probe was redirected to suspected auth endpoint: " + location
                        );
                    }
                }
            }
        }

        // ── 3. Set-Cookie Invalidation Headers ──
        if (config.isCheckSetCookieInvalidation()) {
            for (HttpHeader header : response.headers()) {
                if (header.name().equalsIgnoreCase("Set-Cookie")) {
                    String val = header.value().toLowerCase(Locale.ROOT);
                    if (val.contains("max-age=0") ||
                        val.contains("expires=thu, 01 jan 1970") ||
                        val.contains("1970") ||
                        val.contains("=deleted") ||
                        val.contains("deleted;")) {
                        return ExpirationResult.expired(
                                "Set-Cookie Invalidation",
                                "Response header Set-Cookie explicitly expired or deleted session cookie: " + header.value()
                        );
                    }
                }
            }
        }

        // ── 4. Response Body Expiration Patterns ──
        if (config.isCheckBodyKeywords()) {
            String body = response.bodyToString();
            if (body != null && !body.isEmpty()) {
                String bodyLower = body.toLowerCase(Locale.ROOT);
                List<String> keywords = config.parseBodyKeywords();
                for (String kw : keywords) {
                    if (kw.isEmpty()) continue;
                    try {
                        Pattern p = Pattern.compile(kw, Pattern.CASE_INSENSITIVE);
                        if (p.matcher(body).find()) {
                            return ExpirationResult.expired(
                                    "Body Keyword / Pattern: \"" + kw + "\"",
                                    "Response body matched session expiration pattern: " + kw
                            );
                        }
                    } catch (Exception e) {
                        if (bodyLower.contains(kw.toLowerCase(Locale.ROOT))) {
                            return ExpirationResult.expired(
                                    "Body Keyword: \"" + kw + "\"",
                                    "Response body contains session expiration text: " + kw
                            );
                        }
                    }
                }
            }
        }

        // ── 5. Body Length Drop Threshold ──
        if (config.isCheckBodyLengthDrop()) {
            int bodyLen = response.body().length();
            if (bodyLen > 0 && bodyLen <= config.getBodyLengthDropThreshold() && statusCode != 204 && statusCode != 304) {
                return ExpirationResult.expired(
                        "Body Length Drop (" + bodyLen + " bytes)",
                        "Response body size (" + bodyLen + "B) fell below threshold of " + config.getBodyLengthDropThreshold() + " bytes."
                );
            }
        }

        // ── 6. Custom Regex on Entire Response ──
        if (config.isCheckCustomRegex()) {
            String customRegex = config.getCustomRegexPattern();
            if (customRegex != null && !customRegex.trim().isEmpty()) {
                try {
                    Pattern p = Pattern.compile(customRegex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                    String fullResponse = response.toString();
                    if (p.matcher(fullResponse).find()) {
                        return ExpirationResult.expired(
                                "Custom Regex Match",
                                "Response matched custom regex pattern: " + customRegex
                        );
                    }
                } catch (Exception ignored) {}
            }
        }

        return ExpirationResult.active("Response passed all expiration checks (Status " + statusCode + ")");
    }
}
