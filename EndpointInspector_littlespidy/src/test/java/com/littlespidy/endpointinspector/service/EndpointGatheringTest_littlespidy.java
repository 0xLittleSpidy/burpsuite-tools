// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class EndpointGatheringTest_littlespidy {

    @Test
    @DisplayName("Verify Wayback CDX URL parser extracts unique subdomains and paths")
    void testWaybackUrlParser() {
        List<String> rawCdxLines = List.of(
            "http://example.com/api/v1/users",
            "https://example.com/api/v1/users?id=123",
            "http://admin.example.com/login.php",
            "https://dev.example.com/test/index.html",
            "http://example.com/admin/"
        );

        List<String> subdomains = WaybackUrlParser_littlespidy.extractSubdomains(rawCdxLines, "example.com");
        assertTrue(subdomains.contains("admin.example.com"));
        assertTrue(subdomains.contains("dev.example.com"));
        assertFalse(subdomains.contains("example.com"));

        List<String> paths = WaybackUrlParser_littlespidy.extractPathsForDomain(rawCdxLines, "example.com");
        assertNotNull(paths);
        assertTrue(paths.contains("/api/v1/users"));
        assertTrue(paths.contains("/admin"));

        Map<String, Set<String>> domainPaths = WaybackUrlParser_littlespidy.extractDomainPathsMap(rawCdxLines, "example.com");
        assertTrue(domainPaths.containsKey("admin.example.com"));
        assertTrue(domainPaths.containsKey("dev.example.com"));
    }

    @Test
    @DisplayName("Verify passive extraction from robots.txt content")
    void testParseRobotsTxt() {
        String robotsTxt = """
            User-agent: *
            Disallow: /admin/
            Disallow: /private/secret.key # internal
            Allow: /public/
            Sitemap: https://example.com/sitemap.xml
            """;

        List<String> paths = PassiveExtractor_littlespidy.parseRobotsTxt(robotsTxt);
        assertNotNull(paths);
        assertTrue(paths.contains("/admin/"));
        assertTrue(paths.contains("/private/secret.key"));
        assertTrue(paths.contains("/public/"));
        assertTrue(paths.contains("https://example.com/sitemap.xml"));
    }

    @Test
    @DisplayName("Verify passive extraction from sitemap.xml content")
    void testParseSitemapXml() {
        String sitemapXml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url>
                    <loc>https://example.com/home</loc>
                    <lastmod>2026-01-01</lastmod>
                </url>
                <url>
                    <loc>https://example.com/products/catalog.php</loc>
                </url>
            </urlset>
            """;

        List<String> urls = PassiveExtractor_littlespidy.parseSitemapXml(sitemapXml);
        assertEquals(2, urls.size());
        assertTrue(urls.contains("https://example.com/home"));
        assertTrue(urls.contains("https://example.com/products/catalog.php"));
    }
}
