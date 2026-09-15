// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.hsts.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
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
    String hstsHeader,
    long maxAge,
    boolean includeSubDomains,
    boolean preload,
    HttpRequest request,
    HttpResponse response,
    ZonedDateTime timestamp
) {

    public boolean isMissingHsts() {
        return hstsHeader == null || hstsHeader.isBlank();
    }

    public boolean isOptOut() {
        return !isMissingHsts() && maxAge == 0;
    }

    public boolean isShortMaxAge() {
        return !isMissingHsts() && maxAge > 0 && maxAge < 2_592_000L;
    }

    public boolean isSufficientMaxAge() {
        return !isMissingHsts() && maxAge >= 31_536_000L;
    }

    public String maxAgeSummary() {
        if (isMissingHsts()) return "(missing)";
        if (maxAge < 0)      return "(not set)";
        if (maxAge == 0)     return "0 (opt-out)";
        long days    = maxAge / 86_400;
        long hours   = (maxAge % 86_400) / 3_600;
        if (days > 0) return days + " day" + (days != 1 ? "s" : "");
        return hours + " hour" + (hours != 1 ? "s" : "");
    }

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
