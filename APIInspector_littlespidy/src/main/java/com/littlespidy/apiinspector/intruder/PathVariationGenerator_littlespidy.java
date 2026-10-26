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
     * Generates parent endpoint path variations for API Endpoint Discovery by progressively
     * removing path segments from right to left.
     * All GET query parameters are removed.
     * Example: /api/admin/health?page=1 -> ["/api/admin", "/api", "/"]
     */
    public static List<String> generateEndpointDiscoveryPaths(String originalFullPath) {
        List<String> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        String pathOnly = extractPathOnly(originalFullPath);
        List<String> segments = splitSegments(pathOnly);

        if (segments.isEmpty()) {
            return List.of("/");
        }

        // Generate parent endpoint paths from right to left without GET parameters
        for (int count = segments.size() - 1; count >= 0; count--) {
            StringBuilder sb = new StringBuilder();
            if (count == 0) {
                sb.append("/");
            } else {
                for (int i = 0; i < count; i++) {
                    sb.append("/").append(segments.get(i));
                }
            }

            String candidate = sb.toString();
            if (!candidate.equals(pathOnly) && seen.add(candidate)) {
                results.add(candidate);
            }
        }

        if (results.isEmpty()) {
            results.add("/");
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
