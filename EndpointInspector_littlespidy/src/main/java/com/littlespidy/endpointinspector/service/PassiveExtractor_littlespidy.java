// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive endpoint extraction from robots.txt and sitemap.xml ported from reKover.
 *
 * @author littlespidy
 */
public final class PassiveExtractor_littlespidy {

    private static final Pattern ROBOTS_DIRECTIVE = Pattern.compile(
        "(?i)^(?:Disallow|Allow|Sitemap):\\s*(\\S+)"
    );

    private static final Pattern SITEMAP_LOC = Pattern.compile(
        "(?i)<loc>([^<]+)</loc>"
    );

    private PassiveExtractor_littlespidy() {}

    /**
     * Extracts path directives from a robots.txt response body.
     */
    public static List<String> parseRobotsTxt(String body) {
        if (body == null || body.isBlank() || !body.toLowerCase().contains("user-agent")) {
            return Collections.emptyList();
        }

        Set<String> paths = new LinkedHashSet<>();
        try (BufferedReader reader = new BufferedReader(new StringReader(body))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                Matcher m = ROBOTS_DIRECTIVE.matcher(trimmed);
                if (m.find()) {
                    String path = m.group(1).trim();
                    if (!path.isEmpty() && !path.equals("/")) {
                        paths.add(path);
                    }
                }
            }
        } catch (Exception ignored) {}

        return new ArrayList<>(paths);
    }

    /**
     * Extracts location URLs from a sitemap.xml response body.
     */
    public static List<String> parseSitemapXml(String body) {
        if (body == null || body.isBlank() || !body.toLowerCase().contains("<loc>")) {
            return Collections.emptyList();
        }

        Set<String> urls = new LinkedHashSet<>();
        Matcher m = SITEMAP_LOC.matcher(body);
        while (m.find()) {
            String loc = m.group(1).trim();
            if (!loc.isEmpty()) {
                urls.add(loc);
            }
        }

        return new ArrayList<>(urls);
    }
}
