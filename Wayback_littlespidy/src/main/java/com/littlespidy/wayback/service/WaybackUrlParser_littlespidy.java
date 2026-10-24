// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.service;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class WaybackUrlParser_littlespidy {

    public static List<String> extractPathsForDomain(Collection<String> rawUrls, String targetDomain) {
        if (rawUrls == null || targetDomain == null || targetDomain.isBlank()) {
            return Collections.emptyList();
        }

        String normalizedTarget = targetDomain.trim().toLowerCase();
        Set<String> uniquePaths = new TreeSet<>();

        for (String line : rawUrls) {
            if (line == null || line.isBlank()) {
                continue;
            }

            String urlStr = line.trim();
            // Handle space-separated CDX format if multiple fields returned
            if (urlStr.contains(" ")) {
                String[] parts = urlStr.split("\\s+");
                for (String part : parts) {
                    if (part.startsWith("http://") || part.startsWith("https://")) {
                        urlStr = part;
                        break;
                    }
                }
            }

            try {
                if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
                    urlStr = "http://" + urlStr;
                }

                URI uri = URI.create(urlStr);
                String host = uri.getHost();
                if (host != null && host.toLowerCase().equals(normalizedTarget)) {
                    String path = uri.getPath();
                    if (path != null && !path.isBlank() && !path.equals("/")) {
                        // Normalize path: strip trailing slash
                        while (path.endsWith("/") && path.length() > 1) {
                            path = path.substring(0, path.length() - 1);
                        }
                        if (!path.isBlank() && !path.equals("/")) {
                            uniquePaths.add(path);
                        }
                    }
                }
            } catch (Exception ignored) {
                // Ignore malformed URL entries from CDX
            }
        }

        return new ArrayList<>(uniquePaths);
    }

    public static Map<String, Set<String>> extractDomainPathsMap(Collection<String> rawUrls, String baseDomain) {
        if (rawUrls == null || baseDomain == null || baseDomain.isBlank()) {
            return Collections.emptyMap();
        }

        String normalizedBase = baseDomain.trim().toLowerCase();
        Map<String, Set<String>> domainPaths = new TreeMap<>();

        for (String line : rawUrls) {
            if (line == null || line.isBlank()) continue;

            String urlStr = line.trim();
            if (urlStr.contains(" ")) {
                String[] parts = urlStr.split("\\s+");
                for (String part : parts) {
                    if (part.startsWith("http://") || part.startsWith("https://")) {
                        urlStr = part;
                        break;
                    }
                }
            }

            try {
                if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
                    urlStr = "http://" + urlStr;
                }

                URI uri = URI.create(urlStr);
                String host = uri.getHost();
                if (host != null) {
                    host = host.toLowerCase();
                    if (host.equals(normalizedBase) || host.endsWith("." + normalizedBase)) {
                        String path = uri.getPath();
                        if (path != null && !path.isBlank() && !path.equals("/")) {
                            while (path.endsWith("/") && path.length() > 1) {
                                path = path.substring(0, path.length() - 1);
                            }
                            if (!path.isBlank() && !path.equals("/")) {
                                domainPaths.computeIfAbsent(host, k -> new TreeSet<>()).add(path);
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }

        return domainPaths;
    }

    public static List<String> extractSubdomains(Collection<String> rawUrls, String baseDomain) {
        if (rawUrls == null || baseDomain == null || baseDomain.isBlank()) {
            return Collections.emptyList();
        }

        String normalizedBase = baseDomain.trim().toLowerCase();
        Set<String> subdomains = new TreeSet<>();

        for (String line : rawUrls) {
            if (line == null || line.isBlank()) continue;

            String urlStr = line.trim();
            if (urlStr.contains(" ")) {
                String[] parts = urlStr.split("\\s+");
                for (String part : parts) {
                    if (part.startsWith("http://") || part.startsWith("https://")) {
                        urlStr = part;
                        break;
                    }
                }
            }

            try {
                if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
                    urlStr = "http://" + urlStr;
                }

                URI uri = URI.create(urlStr);
                String host = uri.getHost();
                if (host != null) {
                    host = host.toLowerCase();
                    if (host.endsWith("." + normalizedBase) && !host.equals(normalizedBase)) {
                        subdomains.add(host);
                    }
                }
            } catch (Exception ignored) {
            }
        }

        return new ArrayList<>(subdomains);
    }
}
