// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;

/**
 * Immutable record capturing a single HTTP response's Strict-Transport-Security header
 * and associated parsed values, plus the underlying request/response objects.
 *
 * @author littlespidy
 */
public record HSTSEntry(
    int id,
    String url,
    String host,
    String path,
    String method,
    int statusCode,
    String contentType,
    String hstsHeader,           // raw Strict-Transport-Security value, empty if missing
    long maxAge,                 // parsed max-age seconds, -1 if not present / missing header
    boolean includeSubDomains,
    boolean preload,
    HttpRequest request,
    HttpResponse response,
    ZonedDateTime timestamp
) {

    // ── Derived state helpers ────────────────────────────────────────────────

    /** True when no Strict-Transport-Security header was present at all. */
    public boolean isMissingHsts() {
        return hstsHeader == null || hstsHeader.isBlank();
    }

    /** True when header is present but max-age is explicitly 0 (HSTS opt-out). */
    public boolean isOptOut() {
        return !isMissingHsts() && maxAge == 0;
    }

    /** True when max-age < 30 days (2,592,000 s) — dangerously short. */
    public boolean isShortMaxAge() {
        return !isMissingHsts() && maxAge > 0 && maxAge < 2_592_000L;
    }

    /** True when max-age >= 1 year (31,536,000 s) — recommended minimum. */
    public boolean isSufficientMaxAge() {
        return !isMissingHsts() && maxAge >= 31_536_000L;
    }

    /**
     * Returns a human-readable duration string for max-age (e.g. "365 days").
     */
    public String maxAgeSummary() {
        if (isMissingHsts()) return "(missing)";
        if (maxAge < 0)      return "(not set)";
        if (maxAge == 0)     return "0 (opt-out)";
        long days    = maxAge / 86_400;
        long hours   = (maxAge % 86_400) / 3_600;
        if (days > 0) return days + " day" + (days != 1 ? "s" : "");
        return hours + " hour" + (hours != 1 ? "s" : "");
    }

    /**
     * Returns an assessment string used to colour-code table rows.
     * Format: "SEVERITY – explanation"
     */
    public String assessment() {
        if (isMissingHsts())    return "CRITICAL – Missing HSTS header";
        if (isOptOut())         return "CRITICAL – max-age=0 (HSTS disabled)";
        if (isShortMaxAge())    return "HIGH – max-age < 30 days (" + maxAgeSummary() + ")";
        if (maxAge < 31_536_000L) {
            return "MEDIUM – max-age < 1 year (" + maxAgeSummary() + ")";
        }
        if (!includeSubDomains) return "MEDIUM – Missing includeSubDomains";
        if (!preload)           return "GOOD – HSTS set, consider adding preload";
        return "GOOD – Best practice (max-age + includeSubDomains + preload)";
    }
}
