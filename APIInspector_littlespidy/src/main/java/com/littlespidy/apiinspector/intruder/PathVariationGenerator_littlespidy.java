// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.intruder;

import java.util.*;

/**
 * Generates path variations for API Documentation and API Endpoint Discovery Intruder strategies.
 */
public class PathVariationGenerator_littlespidy {

    /**
     * Generates path variations for the API Documentation strategy by progressively
     * removing path segments from the end towards the root path.
     * Example: /api/v1/admin -> ["/api/v1/", "/api/", "/"]
     */
    public static List<String> generateDocumentationPaths(String originalFullPath) {
        List<String> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        String pathOnly = extractPathOnly(originalFullPath);
        String query = extractQueryString(originalFullPath);
        List<String> segments = splitSegments(pathOnly);

        if (segments.isEmpty()) {
            return List.of("/" + query);
        }

        // Progressively remove segments from the right (end)
        for (int count = segments.size() - 1; count >= 0; count--) {
            StringBuilder sb = new StringBuilder();
            if (count == 0) {
                sb.append("/");
            } else {
                for (int i = 0; i < count; i++) {
                    sb.append("/").append(segments.get(i));
                }
                sb.append("/");
            }

            String candidate = sb.toString() + query;
            if (!candidate.equals(originalFullPath) && seen.add(candidate)) {
                results.add(candidate);
            }
        }

        if (results.isEmpty()) {
            results.add("/" + query);
        }

        return results;
    }

    /**
     * Generates path variations for API Endpoint Discovery by progressively removing
     * both prefix segments and trailing segments to discover unmapped or alternative endpoints.
     * Example: /api/v1/admin -> ["/v1/admin", "/admin", "/api/v1/", "/api/", "/"]
     */
    public static List<String> generateEndpointDiscoveryPaths(String originalFullPath) {
        List<String> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        String pathOnly = extractPathOnly(originalFullPath);
        String query = extractQueryString(originalFullPath);
        List<String> segments = splitSegments(pathOnly);

        if (segments.isEmpty()) {
            return List.of("/" + query);
        }

        seen.add(originalFullPath);

        // 1. Progressive prefix removal (left-to-right)
        for (int start = 1; start < segments.size(); start++) {
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < segments.size(); i++) {
                sb.append("/").append(segments.get(i));
            }
            if (pathOnly.endsWith("/") && !sb.toString().endsWith("/")) {
                sb.append("/");
            }
            String candidate = sb.toString() + query;
            if (seen.add(candidate)) {
                results.add(candidate);
            }
        }

        // 2. Progressive suffix removal (right-to-left)
        for (int count = segments.size() - 1; count >= 0; count--) {
            StringBuilder sb = new StringBuilder();
            if (count == 0) {
                sb.append("/");
            } else {
                for (int i = 0; i < count; i++) {
                    sb.append("/").append(segments.get(i));
                }
                sb.append("/");
            }
            String candidate = sb.toString() + query;
            if (seen.add(candidate)) {
                results.add(candidate);
            }
        }

        if (results.isEmpty()) {
            results.add("/" + query);
        }

        return results;
    }

    public static String extractPathOnly(String fullPath) {
        if (fullPath == null || fullPath.isBlank()) {
            return "/";
        }
        int qIdx = fullPath.indexOf('?');
        return (qIdx != -1) ? fullPath.substring(0, qIdx) : fullPath;
    }

    public static String extractQueryString(String fullPath) {
        if (fullPath == null || fullPath.isBlank()) {
            return "";
        }
        int qIdx = fullPath.indexOf('?');
        return (qIdx != -1) ? fullPath.substring(qIdx) : "";
    }

    public static List<String> splitSegments(String pathOnly) {
        List<String> segments = new ArrayList<>();
        if (pathOnly == null || pathOnly.isEmpty() || "/".equals(pathOnly)) {
            return segments;
        }

        String[] tokens = pathOnly.split("/");
        for (String t : tokens) {
            String trimmed = t.trim();
            if (!trimmed.isEmpty()) {
                segments.add(trimmed);
            }
        }
        return segments;
    }
}
