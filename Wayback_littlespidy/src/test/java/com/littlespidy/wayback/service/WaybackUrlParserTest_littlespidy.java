// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.service;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class WaybackUrlParserTest_littlespidy {

    @Test
    public void testExtractPathsForDomain() {
        List<String> rawUrls = List.of(
                "http://example.com/admin/",
                "http://example.com/admin/index.php",
                "https://example.com/backup",
                "https://example.com/backup/",
                "http://example.com/",
                "https://sub.example.com/secret/",
                "http://otherdomain.org/path"
        );

        List<String> paths = WaybackUrlParser_littlespidy.extractPathsForDomain(rawUrls, "example.com");
        assertEquals(3, paths.size());
        assertTrue(paths.contains("/admin"));
        assertTrue(paths.contains("/admin/index.php"));
        assertTrue(paths.contains("/backup"));
        assertFalse(paths.contains("/secret"));
    }

    @Test
    public void testExtractSubdomains() {
        List<String> rawUrls = List.of(
                "http://example.com/test",
                "http://api.example.com/v1",
                "https://admin.example.com/",
                "https://dev.api.example.com/app",
                "http://notexample.com/path"
        );

        List<String> subdomains = WaybackUrlParser_littlespidy.extractSubdomains(rawUrls, "example.com");
        assertEquals(3, subdomains.size());
        assertTrue(subdomains.contains("api.example.com"));
        assertTrue(subdomains.contains("admin.example.com"));
        assertTrue(subdomains.contains("dev.api.example.com"));
        assertFalse(subdomains.contains("example.com"));
    }

    @Test
    public void testExtractDomainPathsMap() {
        List<String> rawUrls = List.of(
                "http://example.com/page1",
                "http://api.example.com/v1/users",
                "http://api.example.com/v1/auth",
                "http://admin.example.com/login"
        );

        Map<String, Set<String>> map = WaybackUrlParser_littlespidy.extractDomainPathsMap(rawUrls, "example.com");
        assertTrue(map.containsKey("example.com"));
        assertTrue(map.containsKey("api.example.com"));
        assertTrue(map.containsKey("admin.example.com"));

        assertEquals(1, map.get("example.com").size());
        assertEquals(2, map.get("api.example.com").size());
        assertEquals(1, map.get("admin.example.com").size());
    }
}
