// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.Set;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Core filter mechanics and reusable predicates following extension_architecture.md.
 * Provides consistent status code, domain, content-type, method, and scope filtering.
 *
 * @author littlespidy
 */
public final class FilterUtils {

    private FilterUtils() {}

    /**
     * Functional interface for simplified Swing DocumentListener with debouncing.
     */
    @FunctionalInterface
    public interface SimpleDocumentListener extends DocumentListener {
        void update();

        @Override
        default void insertUpdate(DocumentEvent e) { update(); }

        @Override
        default void removeUpdate(DocumentEvent e) { update(); }

        @Override
        default void changedUpdate(DocumentEvent e) { update(); }
    }

    /**
     * Tests if an HTTP status code matches a text filter (ranges like 2xx, comma-separated codes, etc.).
     */
    public static boolean matchesStatusCode(int statusCode, String filter) {
        if (filter == null || filter.trim().isEmpty() || filter.equalsIgnoreCase("All") || filter.equalsIgnoreCase("All Statuses") || filter.equalsIgnoreCase("All Status Codes")) {
            return true;
        }
        if (statusCode <= 0) return false;

        String[] tokens = filter.split("[,/\\s]+");
        for (String rawToken : tokens) {
            String token = rawToken.trim();
            if (token.isEmpty()) continue;

            if (token.equalsIgnoreCase("2xx") && statusCode >= 200 && statusCode < 300) return true;
            if (token.equalsIgnoreCase("3xx") && statusCode >= 300 && statusCode < 400) return true;
            if (token.equalsIgnoreCase("4xx") && statusCode >= 400 && statusCode < 500) return true;
            if (token.equalsIgnoreCase("5xx") && statusCode >= 500 && statusCode < 600) return true;

            try {
                int targetCode = Integer.parseInt(token);
                if (statusCode == targetCode) return true;
            } catch (NumberFormatException ignored) {}
        }
        return false;
    }

    /**
     * Tests if an HTTP status code matches a set of selected options from MultiSelectFilterButton.
     */
    public static boolean matchesStatusCode(int statusCode, Set<String> selectedOptions) {
        if (selectedOptions == null || selectedOptions.isEmpty()) {
            return true;
        }
        if (statusCode <= 0) return false;

        for (String option : selectedOptions) {
            String opt = option.trim().toLowerCase();
            if (opt.startsWith("all")) return true;

            // Range checks
            if (opt.startsWith("2xx") && statusCode >= 200 && statusCode < 300) return true;
            if (opt.startsWith("3xx") && statusCode >= 300 && statusCode < 400) return true;
            if (opt.startsWith("4xx") && statusCode >= 400 && statusCode < 500) return true;
            if (opt.startsWith("5xx") && statusCode >= 500 && statusCode < 600) return true;

            // Specific status codes
            if (opt.startsWith("200") && statusCode == 200) return true;
            if (opt.startsWith("201") && statusCode == 201) return true;
            if (opt.startsWith("204") && statusCode == 204) return true;
            if (opt.contains("301") && statusCode == 301) return true;
            if (opt.contains("302") && statusCode == 302) return true;
            if (opt.contains("304") && statusCode == 304) return true;
            if (opt.startsWith("400") && statusCode == 400) return true;
            if (opt.startsWith("401") && statusCode == 401) return true;
            if (opt.startsWith("403") && statusCode == 403) return true;
            if (opt.startsWith("404") && statusCode == 404) return true;
            if (opt.startsWith("405") && statusCode == 405) return true;
            if (opt.startsWith("500") && statusCode == 500) return true;
            if (opt.startsWith("502") && statusCode == 502) return true;
            if (opt.startsWith("503") && statusCode == 503) return true;

            // Generic fallback extraction of first 3-digit number
            try {
                String firstNum = opt.replaceAll("[^0-9]", " ").trim().split("\\s+")[0];
                if (!firstNum.isEmpty() && Integer.parseInt(firstNum) == statusCode) {
                    return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }

    /**
     * Sanitizes and matches an entry's host against a domain filter input.
     * Supports exact match, subdomain wildcard suffix, or substring match.
     */
    public static boolean matchesDomain(String entryHost, String domainFilter) {
        if (domainFilter == null || domainFilter.trim().isEmpty() || domainFilter.equalsIgnoreCase("All")) {
            return true;
        }
        if (entryHost == null || entryHost.isEmpty()) return false;

        // 1. Sanitize user input (strip protocol, port, paths, wildcard prefixes)
        String cleanFilter = domainFilter.trim().toLowerCase();
        if (cleanFilter.startsWith("http://")) cleanFilter = cleanFilter.substring(7);
        if (cleanFilter.startsWith("https://")) cleanFilter = cleanFilter.substring(8);
        int slashIdx = cleanFilter.indexOf('/');
        if (slashIdx != -1) cleanFilter = cleanFilter.substring(0, slashIdx);
        int colonIdx = cleanFilter.indexOf(':');
        if (colonIdx != -1) cleanFilter = cleanFilter.substring(0, colonIdx);
        if (cleanFilter.startsWith("*.")) cleanFilter = cleanFilter.substring(2);

        if (cleanFilter.isEmpty()) return true;

        // 2. Sanitize entry host (strip port if present)
        String host = entryHost.toLowerCase();
        int hostColon = host.indexOf(':');
        if (hostColon != -1) host = host.substring(0, hostColon);

        // 3. Match: Exact host, subdomain suffix, or contains
        return host.equalsIgnoreCase(cleanFilter)
            || host.endsWith("." + cleanFilter)
            || host.contains(cleanFilter);
    }

    /**
     * Non-destructive view filter evaluated live against Burp's target scope.
     */
    public static boolean matchesScope(MontoyaApi api, String url, boolean inScopeOnly) {
        if (!inScopeOnly) return true;
        if (url == null || api == null) return false;
        try {
            return api.scope().isInScope(url);
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Matches standard HTTP methods.
     */
    public static boolean matchesMethod(String method, Set<String> selectedMethods) {
        if (selectedMethods == null || selectedMethods.isEmpty() || selectedMethods.contains("All Methods")) {
            return true;
        }
        if (method == null) return false;
        return selectedMethods.contains(method.toUpperCase());
    }

    /**
     * Matches candidate Content-Type against user-selected Content-Types.
     */
    public static boolean matchesContentType(String contentType, Set<String> selectedTypes) {
        if (selectedTypes == null || selectedTypes.isEmpty()) {
            return true;
        }
        String cType = (contentType == null) ? "" : contentType.toLowerCase();

        for (String opt : selectedTypes) {
            String lower = opt.toLowerCase();
            if (lower.startsWith("all")) return true;

            if (lower.contains("form") && (cType.contains("x-www-form-urlencoded") || cType.contains("form"))) return true;
            if (lower.contains("json") && cType.contains("json")) return true;
            if (lower.contains("multipart") && cType.contains("multipart")) return true;
            if (lower.contains("xml") && cType.contains("xml")) return true;
            if (lower.contains("plain") && cType.contains("text/plain")) return true;
            if (lower.contains("html") && cType.contains("html")) return true;
            if (lower.contains("other") && !cType.contains("json") && !cType.contains("form") && !cType.contains("multipart") && !cType.contains("xml")) return true;
        }
        return false;
    }

    /**
     * Matches candidate parameter types (BODY, JSON, MULTIPART, URL) against selected types.
     */
    public static boolean matchesParamTypes(Set<String> candidateParamTypes, Set<String> selectedTypes) {
        if (selectedTypes == null || selectedTypes.isEmpty()) {
            return true;
        }
        if (candidateParamTypes == null || candidateParamTypes.isEmpty()) {
            return false;
        }

        for (String opt : selectedTypes) {
            String lower = opt.toLowerCase();
            if (lower.startsWith("all")) return true;

            if (lower.contains("body") && candidateParamTypes.contains("BODY")) return true;
            if (lower.contains("json") && candidateParamTypes.contains("JSON")) return true;
            if (lower.contains("multipart") && candidateParamTypes.contains("MULTIPART")) return true;
            if (lower.contains("url") && candidateParamTypes.contains("URL")) return true;
            if (lower.contains("xml") && candidateParamTypes.contains("XML")) return true;
        }
        return false;
    }
}
