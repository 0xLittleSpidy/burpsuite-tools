// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.model;

import java.util.*;

/**
 * Utility class to parse Content Security Policy strings into structured directive maps.
 *
 * @author littlespidy
 */
public class CSPParser {

    public static final List<String> COMMON_DIRECTIVES = List.of(
        "default-src",
        "script-src",
        "script-src-elem",
        "script-src-attr",
        "style-src",
        "style-src-elem",
        "style-src-attr",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "media-src",
        "frame-src",
        "child-src",
        "frame-ancestors",
        "form-action",
        "base-uri",
        "manifest-src",
        "worker-src",
        "report-uri",
        "report-to",
        "upgrade-insecure-requests",
        "block-all-mixed-content"
    );

    /**
     * Parses a raw CSP header string (e.g., "default-src 'self'; script-src 'unsafe-inline' https://cdn.example.com")
     * into a LinkedHashMap mapping lowercase directive names to lists of source expressions.
     */
    public static Map<String, List<String>> parsePolicy(String rawPolicy) {
        Map<String, List<String>> directiveMap = new LinkedHashMap<>();
        if (rawPolicy == null || rawPolicy.trim().isEmpty()) {
            return directiveMap;
        }

        String[] directives = rawPolicy.split(";");
        for (String directive : directives) {
            String trimmed = directive.trim();
            if (trimmed.isEmpty()) continue;

            String[] tokens = trimmed.split("\\s+");
            if (tokens.length == 0) continue;

            String directiveName = tokens[0].toLowerCase().trim();
            List<String> values = new ArrayList<>();
            for (int i = 1; i < tokens.length; i++) {
                String token = tokens[i].trim();
                if (!token.isEmpty()) {
                    values.add(token);
                }
            }
            directiveMap.put(directiveName, values);
        }

        return directiveMap;
    }
}
