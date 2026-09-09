// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Webpack chunk extractor ported from js-recon.
 * Parses webpack runtime chunk-loading patterns (object maps, if-chains, and string-keyed maps)
 * to statically discover and reconstruct hidden, lazy-loaded chunk bundle URLs.
 *
 * @author littlespidy
 */
public final class WebpackChunkExtractor {

    private WebpackChunkExtractor() {}

    // Pattern 1: Object map { 123: "name", 456: "name2" }[e] + ".js"
    private static final Pattern OBJECT_MAP_PATTERN = Pattern.compile(
        "\\{((?:\\s*\\d+\\s*:\\s*[\"'][^\"']+[\"']\\s*,?){2,})\\}"
    );
    private static final Pattern ENTRY_PAIR_PATTERN = Pattern.compile(
        "\\s*(\\d+)\\s*:\\s*[\"']([^\"']+)[\"']"
    );

    // Pattern 2: If-chain pattern: if (123 === e) return "name.js";
    private static final Pattern IF_CHAIN_PATTERN = Pattern.compile(
        "if\\s*\\(\\s*(?:\\d+\\s*===|\\w+\\s*===)\\s*\\w+\\s*\\)\\s*return\\s*[\"']([^\"']+\\.js)[\"']"
    );

    // Pattern 3: String-keyed hash map: { "about": "a1b2c3", "profile": "d4e5f6" }[e]
    private static final Pattern STRING_KEYED_MAP_PATTERN = Pattern.compile(
        "\\{((?:\\s*[\"'][a-zA-Z0-9_.-]+[\"']\\s*:\\s*[\"'][a-zA-Z0-9_.-]+[\"']\\s*,?){2,})\\}"
    );
    private static final Pattern STRING_PAIR_PATTERN = Pattern.compile(
        "[\"']([a-zA-Z0-9_.-]+)[\"']\\s*:\\s*[\"']([a-zA-Z0-9_.-]+)[\"']"
    );

    // Pattern 4: Chunk suffix template: + ".chunk.js" or + ".bundle.js" or + ".js"
    private static final Pattern CHUNK_TEMPLATE_PATTERN = Pattern.compile(
        "\\+\\s*[\"'](\\.chunk\\.js|\\.bundle\\.js|\\.js)[\"']"
    );

    /**
     * Extracts resolved lazy-loaded chunk URLs from the JavaScript content.
     *
     * @param baseUrl the URL of the JS file currently being parsed
     * @param jsContent the JavaScript body text
     * @return set of fully resolved chunk URLs
     */
    public static Set<String> extractChunkUrls(String baseUrl, String jsContent) {
        Set<String> result = new LinkedHashSet<>();
        if (baseUrl == null || jsContent == null) {
            return result;
        }

        // Defensive: handle swapped arguments
        if (!baseUrl.startsWith("http") && jsContent.startsWith("http")) {
            String tmp = baseUrl;
            baseUrl = jsContent;
            jsContent = tmp;
        }

        if (jsContent.length() < 20) {
            return result;
        }

        // Limit scanning to 5MB to avoid heap stalls
        String content = jsContent.length() > 5_000_000 ? jsContent.substring(0, 5_000_000) : jsContent;

        // Determine chunk suffix (default ".js")
        String suffix = ".js";
        Matcher suffMatcher = CHUNK_TEMPLATE_PATTERN.matcher(content);
        if (suffMatcher.find()) {
            suffix = suffMatcher.group(1);
        }

        // 1. Numeric Object-Map Extraction
        Matcher objMatcher = OBJECT_MAP_PATTERN.matcher(content);
        while (objMatcher.find()) {
            String mapBlock = objMatcher.group(1);
            Matcher pairMatcher = ENTRY_PAIR_PATTERN.matcher(mapBlock);
            int count = 0;
            List<String> names = new ArrayList<>();
            while (pairMatcher.find()) {
                count++;
                names.add(pairMatcher.group(2));
            }
            if (count >= 2) {
                for (String name : names) {
                    String candidate = name.endsWith(".js") ? name : name + suffix;
                    String resolved = resolveChunkUrl(baseUrl, candidate);
                    if (resolved != null) result.add(resolved);
                }
            }
        }

        // 2. If-Chain Extraction
        Matcher ifMatcher = IF_CHAIN_PATTERN.matcher(content);
        while (ifMatcher.find()) {
            String filename = ifMatcher.group(1);
            String resolved = resolveChunkUrl(baseUrl, filename);
            if (resolved != null) result.add(resolved);
        }

        // 3. String-Keyed Map Extraction
        Matcher strMapMatcher = STRING_KEYED_MAP_PATTERN.matcher(content);
        while (strMapMatcher.find()) {
            String block = strMapMatcher.group(1);
            Matcher pairMatcher = STRING_PAIR_PATTERN.matcher(block);
            int count = 0;
            List<String> combined = new ArrayList<>();
            while (pairMatcher.find()) {
                count++;
                String name = pairMatcher.group(1);
                String hash = pairMatcher.group(2);
                combined.add(name + "." + hash + suffix);
            }
            if (count >= 2) {
                for (String c : combined) {
                    String resolved = resolveChunkUrl(baseUrl, c);
                    if (resolved != null) result.add(resolved);
                }
            }
        }

        return result;
    }

    private static String resolveChunkUrl(String baseUrl, String candidate) {
        if (candidate == null || candidate.trim().isEmpty()) return null;
        try {
            URI baseUri = new URI(baseUrl);
            URI resolved = baseUri.resolve(candidate.trim());
            return resolved.toString();
        } catch (Exception ex) {
            return null;
        }
    }
}
