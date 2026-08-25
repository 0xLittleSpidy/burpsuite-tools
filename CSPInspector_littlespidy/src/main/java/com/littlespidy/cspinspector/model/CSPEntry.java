// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.*;

/**
 * Immutable record capturing a single HTTP response's Content Security Policy headers,
 * parsed directives, and underlying request/response objects.
 *
 * @author littlespidy
 */
public record CSPEntry(
    int id,
    String url,
    String host,
    String path,
    String method,
    int statusCode,
    String contentType,
    String cspHeader,
    String cspReportOnlyHeader,
    String xCspHeader,
    String xWebKitCspHeader,
    Map<String, List<String>> parsedDirectives,
    HttpRequest request,
    HttpResponse response,
    ZonedDateTime timestamp
) {

    public boolean isMissingCsp() {
        return (cspHeader == null || cspHeader.trim().isEmpty())
                && (cspReportOnlyHeader == null || cspReportOnlyHeader.trim().isEmpty())
                && (xCspHeader == null || xCspHeader.trim().isEmpty())
                && (xWebKitCspHeader == null || xWebKitCspHeader.trim().isEmpty());
    }

    public boolean isReportOnly() {
        return (cspHeader == null || cspHeader.trim().isEmpty())
                && (cspReportOnlyHeader != null && !cspReportOnlyHeader.trim().isEmpty());
    }

    public String getPrimaryCsp() {
        if (cspHeader != null && !cspHeader.trim().isEmpty()) return cspHeader.trim();
        if (cspReportOnlyHeader != null && !cspReportOnlyHeader.trim().isEmpty()) return cspReportOnlyHeader.trim();
        if (xCspHeader != null && !xCspHeader.trim().isEmpty()) return xCspHeader.trim();
        if (xWebKitCspHeader != null && !xWebKitCspHeader.trim().isEmpty()) return xWebKitCspHeader.trim();
        return "(missing CSP)";
    }

    public List<String> getDirectiveTokens(String directiveName) {
        if (parsedDirectives == null) return Collections.emptyList();
        return parsedDirectives.getOrDefault(directiveName.toLowerCase().trim(), Collections.emptyList());
    }

    public String getDirectiveString(String directiveName) {
        List<String> tokens = getDirectiveTokens(directiveName);
        if (tokens.isEmpty()) return "(not set)";
        return String.join(" ", tokens);
    }

    public boolean hasDirective(String directiveName) {
        if (parsedDirectives == null) return false;
        return parsedDirectives.containsKey(directiveName.toLowerCase().trim());
    }

    public boolean directiveContains(String directiveName, String tokenSubstring) {
        List<String> tokens = getDirectiveTokens(directiveName);
        for (String t : tokens) {
            if (t.toLowerCase().contains(tokenSubstring.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public boolean hasUnsafeInline() {
        return directiveContains("script-src", "'unsafe-inline'")
                || (!hasDirective("script-src") && directiveContains("default-src", "'unsafe-inline'"))
                || directiveContains("style-src", "'unsafe-inline'");
    }

    public boolean hasUnsafeEval() {
        return directiveContains("script-src", "'unsafe-eval'")
                || (!hasDirective("script-src") && directiveContains("default-src", "'unsafe-eval'"));
    }

    public boolean hasWildcard() {
        if (parsedDirectives == null) return false;
        for (List<String> tokens : parsedDirectives.values()) {
            for (String t : tokens) {
                if (t.equals("*") || t.startsWith("http:") || t.startsWith("https://*") || t.equals("data:")) {
                    return true;
                }
            }
        }
        return false;
    }
}
