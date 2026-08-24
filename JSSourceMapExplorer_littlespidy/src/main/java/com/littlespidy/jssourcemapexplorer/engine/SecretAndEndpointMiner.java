// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredEndpoint;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredSecret;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans JavaScript code (raw JS assets or unpacked source map files) for
 * hardcoded secrets, sensitive credentials, and API routes/endpoints.
 *
 * @author littlespidy
 */
public class SecretAndEndpointMiner {

    private static final List<SecretPattern> SECRET_PATTERNS = List.of(
        new SecretPattern("JSON Web Token (JWT)", Pattern.compile("eyJ[A-Za-z0-9-_]{10,}\\.eyJ[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,}")),
        new SecretPattern("Google API Key", Pattern.compile("AIza[0-9A-Za-z-_]{35}")),
        new SecretPattern("Stripe Secret Key", Pattern.compile("(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}")),
        new SecretPattern("GitHub Token", Pattern.compile("(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}")),
        new SecretPattern("AWS Access Key ID", Pattern.compile("(?:AKIA|ASIA)[0-9A-Z]{16}")),
        new SecretPattern("Private Key Header", Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
        new SecretPattern("Authorization Header", Pattern.compile("(?i)['\"](?:Authorization|Bearer)\\s*[:=]\\s*['\"]?(Bearer\\s+[a-zA-Z0-9_\\-\\.]{20,})['\"]?")),
        new SecretPattern("Generic API Secret Key", Pattern.compile("(?i)['\"](?:api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret)['\"]\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{16,})['\"]")),
        new SecretPattern("Firebase API Key", Pattern.compile("(?i)['\"](?:apiKey|appId)['\"]\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{20,})['\"]")),
        new SecretPattern("Developer Flag / Comment", Pattern.compile("(?i)(?:TODO|FIXME|BUG|HACK|DEBUG|DEPRECATED):?\\s*(.{5,80})"))
    );

    private static final Pattern ENDPOINT_PATTERN = Pattern.compile(
        "['\"](/(?:api|v[0-9]|graphql|admin|internal|user|auth|oauth|webhook|rest|service|v1|v2|v3)/[a-zA-Z0-9_\\-/{}/?&=%#.]*)['\"]"
    );

    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
        "['\"](https?://[a-zA-Z0-9_\\-\\.]+(?::\\d+)?(?:/[a-zA-Z0-9_\\-/{}/?&=%#.]*)?)['\"]"
    );

    private record SecretPattern(String category, Pattern pattern) {}

    public static MiningResult mine(String sourceLocation, String sourceType, String sourceCode) {
        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            return new MiningResult(Collections.emptyList(), Collections.emptyList());
        }

        List<DiscoveredSecret> secrets = new ArrayList<>();
        List<DiscoveredEndpoint> endpoints = new ArrayList<>();
        Set<String> seenEndpoints = new HashSet<>();
        Set<String> seenSecrets = new HashSet<>();

        String[] lines = sourceCode.split("\r?\n");

        for (int i = 0; i < lines.length; i++) {
            int lineNum = i + 1;
            String line = lines[i];

            // 1. Scan for Secrets
            for (SecretPattern sp : SECRET_PATTERNS) {
                Matcher sm = sp.pattern().matcher(line);
                while (sm.find()) {
                    String matchVal = sm.group(sm.groupCount() >= 1 && sm.group(1) != null ? 1 : 0);
                    if (matchVal != null && !matchVal.trim().isEmpty() && !seenSecrets.contains(matchVal)) {
                        seenSecrets.add(matchVal);
                        String context = getSnippet(line, sm.start(), sm.end());
                        secrets.add(new DiscoveredSecret(sourceLocation, sourceType, sp.category(), matchVal, lineNum, context));
                    }
                }
            }

            // 2. Scan for API Endpoints & Absolute URLs
            Matcher epMatcher = ENDPOINT_PATTERN.matcher(line);
            while (epMatcher.find()) {
                String ep = epMatcher.group(1);
                if (ep != null && ep.length() > 3 && !seenEndpoints.contains(ep)) {
                    seenEndpoints.add(ep);
                    String methodGuess = guessMethod(line);
                    String context = getSnippet(line, epMatcher.start(), epMatcher.end());
                    endpoints.add(new DiscoveredEndpoint(sourceLocation, sourceType, ep, methodGuess, lineNum, context));
                }
            }

            Matcher urlMatcher = HTTP_URL_PATTERN.matcher(line);
            while (urlMatcher.find()) {
                String url = urlMatcher.group(1);
                if (url != null && !seenEndpoints.contains(url)) {
                    seenEndpoints.add(url);
                    String methodGuess = guessMethod(line);
                    String context = getSnippet(line, urlMatcher.start(), urlMatcher.end());
                    endpoints.add(new DiscoveredEndpoint(sourceLocation, sourceType, url, methodGuess, lineNum, context));
                }
            }
        }

        return new MiningResult(secrets, endpoints);
    }

    private static String guessMethod(String line) {
        String lower = line.toLowerCase();
        if (lower.contains("post(") || lower.contains("method: 'post'") || lower.contains("method: \"post\"")) return "POST";
        if (lower.contains("get(") || lower.contains("method: 'get'") || lower.contains("method: \"get\"")) return "GET";
        if (lower.contains("put(") || lower.contains("method: 'put'") || lower.contains("method: \"put\"")) return "PUT";
        if (lower.contains("delete(") || lower.contains("method: 'delete'") || lower.contains("method: \"delete\"")) return "DELETE";
        if (lower.contains("patch(") || lower.contains("method: 'patch'") || lower.contains("method: \"patch\"")) return "PATCH";
        return "ROUTE";
    }

    private static String getSnippet(String line, int start, int end) {
        String trimmed = line.trim();
        if (trimmed.length() > 140) {
            return trimmed.substring(0, 137) + "...";
        }
        return trimmed;
    }

    public record MiningResult(
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints
    ) {}
}
