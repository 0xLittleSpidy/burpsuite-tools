// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class RekoverTechniquesTest_littlespidy {

    @Test
    @DisplayName("Verify URL signature normalization collapses parameter value variants")
    void testUrlSignatureNormalization() {
        String url1 = "https://example.com/api/v1/users?id=123&sort=asc&page=2";
        String url2 = "https://example.com/api/v1/users?page=99&sort=desc&id=456";
        String url3 = "/api/v1/users?id=999&sort=none&page=1";

        UrlSignature_littlespidy sig1 = UrlSignature_littlespidy.fromUrl(url1);
        UrlSignature_littlespidy sig2 = UrlSignature_littlespidy.fromUrl(url2);
        UrlSignature_littlespidy sig3 = UrlSignature_littlespidy.fromUrl(url3);

        assertEquals("/api/v1/users", sig1.path());
        assertEquals("id,page,sort", sig1.paramKeys());
        assertEquals("/api/v1/users::id,page,sort", sig1.signature());
        assertEquals(sig1.signature(), sig2.signature(), "Value variants must produce identical signature");
        assertEquals(sig1.signature(), sig3.signature(), "Relative URL must produce identical signature");
    }

    @Test
    @DisplayName("Verify token-level Jaccard similarity calculation")
    void testJaccardSimilarity() {
        String body1 = "<html><body><h1>User Profile</h1><p>User ID: 12345</p><p>Status: Active</p></body></html>";
        String body2 = "<html><body><h1>User Profile</h1><p>User ID: 99881</p><p>Status: Active</p></body></html>";
        String completelyDifferent = "{\"error\": \"Not Found\", \"code\": 404}";

        int simSibling = JaccardSimilarity_littlespidy.calculate(body1, body2);
        int simDiff = JaccardSimilarity_littlespidy.calculate(body1, completelyDifferent);

        assertTrue(simSibling >= 70, "Sibling responses differing only in ID must have high similarity (got: " + simSibling + ")");
        assertTrue(simDiff < 30, "Completely different responses must have low similarity (got: " + simDiff + ")");
        assertEquals(100, JaccardSimilarity_littlespidy.calculate(body1, body1), "Identical bodies must yield 100%");
    }

    @Test
    @DisplayName("Verify Pareto cut ranking keeps vital few within 80% cumulative weight")
    void testParetoCut() {
        List<ParetoCut_littlespidy.WeightedItem<String>> items = List.of(
            new ParetoCut_littlespidy.WeightedItem<>(100L, "/api/popular"),
            new ParetoCut_littlespidy.WeightedItem<>(80L, "/api/common"),
            new ParetoCut_littlespidy.WeightedItem<>(50L, "/api/standard"),
            new ParetoCut_littlespidy.WeightedItem<>(5L, "/api/rare1"),
            new ParetoCut_littlespidy.WeightedItem<>(2L, "/api/rare2"),
            new ParetoCut_littlespidy.WeightedItem<>(1L, "/api/rare3")
        );

        List<String> survivors = ParetoCut_littlespidy.cut(items, 10);
        assertTrue(survivors.contains("/api/popular"));
        assertTrue(survivors.contains("/api/common"));
        assertTrue(survivors.contains("/api/standard"));
        assertFalse(survivors.contains("/api/rare2"), "Tail items exceeding 80% cumulative weight should be dropped");
        assertFalse(survivors.contains("/api/rare3"), "Tail items exceeding 80% cumulative weight should be dropped");
    }

    @Test
    @DisplayName("Verify passive extraction from robots.txt and sitemap.xml")
    void testPassiveExtraction() {
        String robotsTxt = "User-agent: *\n"
                + "Disallow: /admin/\n"
                + "Disallow: /private/api\n"
                + "Allow: /public/\n"
                + "Sitemap: https://example.com/sitemap_index.xml\n";

        List<String> paths = PassiveExtractor_littlespidy.parseRobotsTxt(robotsTxt);
        assertTrue(paths.contains("/admin/"));
        assertTrue(paths.contains("/private/api"));
        assertTrue(paths.contains("/public/"));

        String sitemapXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
                + "  <url><loc>https://example.com/products/view</loc></url>\n"
                + "  <url><loc>https://example.com/checkout/cart</loc></url>\n"
                + "</urlset>";

        List<String> sitemapUrls = PassiveExtractor_littlespidy.parseSitemapXml(sitemapXml);
        assertTrue(sitemapUrls.contains("https://example.com/products/view"));
        assertTrue(sitemapUrls.contains("https://example.com/checkout/cart"));
    }

    @Test
    @DisplayName("Verify probability-weighted Pareto tree wordlist generation")
    void testParetoWordlist() {
        List<String> wordlist = RekoverWordlist_littlespidy.buildWordlist();
        assertFalse(wordlist.isEmpty(), "Wordlist must not be empty");

        assertTrue(wordlist.contains("admin/login"));
        assertTrue(wordlist.contains("api/v1/users"));
        assertTrue(wordlist.contains("api/v1/auth/token"));
        assertTrue(wordlist.contains("actuator/health"));
        assertTrue(wordlist.contains(".env"));
        assertTrue(wordlist.contains("robots.txt"));
    }

    @Test
    @DisplayName("Verify JavaScript-aware endpoint extraction")
    void testJsEndpointExtraction() {
        String jsContent = "const route = '/api/v1/orders';\n"
                + "fetch('/api/v2/analytics/stream', { method: 'POST' });\n"
                + "axios.get('/internal/metrics');\n"
                + "const tpl = `/api/v1/users/${userId}/details`;\n";

        Set<String> endpoints = JsEndpointExtractor_littlespidy.extractEndpoints(jsContent, true);
        assertTrue(endpoints.contains("/api/v1/orders"));
        assertTrue(endpoints.contains("/api/v2/analytics/stream"));
        assertTrue(endpoints.contains("/internal/metrics"));
        assertTrue(endpoints.contains("/api/v1/users"));
    }

    @Test
    @DisplayName("Verify Wayback archive diffing isolates delinked archive-only endpoints")
    void testArchiveDiffing() {
        List<String> cdxRecords = List.of(
            "http://example.com/live/page1 20200101 200",
            "http://example.com/live/page2 20200101 200",
            "http://example.com/hidden/legacy-admin 20190101 200",
            "http://example.com/hidden/legacy-admin 20190201 200",
            "http://example.com/hidden/legacy-admin 20190301 200",
            "http://example.com/old-backup.tar.gz 20180101 200"
        );

        Set<String> liveKnownPaths = Set.of("/live/page1", "/live/page2");

        WaybackArchiveDiffer_littlespidy.ArchiveDiffResult result =
                WaybackArchiveDiffer_littlespidy.diffArchive(cdxRecords, "example.com", liveKnownPaths, 10);

        List<String> survivors = result.survivorUrls();
        assertFalse(survivors.isEmpty(), "Should yield archive-only survivors");
        boolean foundLegacyAdmin = survivors.stream().anyMatch(s -> s.contains("/hidden/legacy-admin"));
        assertTrue(foundLegacyAdmin, "Delinked legacy admin must be surfaced from archive diff");
        boolean foundLivePage1 = survivors.stream().anyMatch(s -> s.contains("/live/page1"));
        assertFalse(foundLivePage1, "Live paths must be subtracted and excluded from archive diff");
    }
}
