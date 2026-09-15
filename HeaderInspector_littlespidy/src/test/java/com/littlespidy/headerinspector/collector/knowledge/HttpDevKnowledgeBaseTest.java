// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.knowledge;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Tests the offline embedded http.dev HTTP header knowledge base.
 *
 * @author littlespidy
 */
class HttpDevKnowledgeBaseTest {

    @Test
    void testLoadsAllHeaders() {
        int count = HttpDevKnowledgeBase.totalCount();
        assertTrue(count >= 300, "Knowledge base should contain at least 300 headers, found: " + count);
        assertEquals(307, count, "Exact expected count of scraped headers is 307");
    }

    @Test
    void testCaseInsensitiveLookups() {
        HttpDevHeaderDoc lower = HttpDevKnowledgeBase.get("cache-control");
        HttpDevHeaderDoc title = HttpDevKnowledgeBase.get("Cache-Control");
        HttpDevHeaderDoc upper = HttpDevKnowledgeBase.get("CACHE-CONTROL");

        assertNotNull(lower, "Lower case lookup should succeed");
        assertNotNull(title, "Title case lookup should succeed");
        assertNotNull(upper, "Upper case lookup should succeed");

        assertEquals("Cache-Control", lower.name());
        assertEquals("Caching", lower.category());
        assertEquals("https://http.dev/cache-control", lower.referenceUrl());
        assertTrue(lower.explanation().contains("Browser and CDN caching behavior"));
        assertTrue(lower.directives().contains("max-age"));
        assertTrue(lower.hasSpecifications());
        assertEquals(3, lower.specifications().size());
    }

    @Test
    void testSecurityHeaders() {
        HttpDevHeaderDoc csp = HttpDevKnowledgeBase.get("Content-Security-Policy");
        assertNotNull(csp);
        assertEquals("Security", csp.category());
        assertTrue(csp.explanation().contains("Cross-site scripting"));
        assertTrue(csp.hasSpecifications());

        HttpDevHeaderDoc hsts = HttpDevKnowledgeBase.get("Strict-Transport-Security");
        assertNotNull(hsts);
        assertEquals("Security", hsts.category());
        assertTrue(hsts.explanation().contains("Strict Transport Security"));
    }

    @Test
    void testVendorHeaders() {
        HttpDevHeaderDoc cfRay = HttpDevKnowledgeBase.get("CF-Ray");
        assertNotNull(cfRay);
        assertEquals("Cloudflare", cfRay.category());

        HttpDevHeaderDoc awsAmz = HttpDevKnowledgeBase.get("x-amz-cf-id");
        assertNotNull(awsAmz);
        assertEquals("AWS", awsAmz.category());
    }

    @Test
    void testUnknownHeaderFallback() {
        HttpDevHeaderDoc doc = HttpDevKnowledgeBase.get("X-Custom-Header-Not-In-Catalog-12345");
        assertNull(doc, "Unknown header should return null");

        String category = HttpDevKnowledgeBase.getCategory("X-Custom-Header-Not-In-Catalog-12345");
        assertEquals("Custom / Vendor", category, "Unknown header category should be Custom / Vendor");
        assertFalse(HttpDevKnowledgeBase.isKnown("X-Custom-Header-Not-In-Catalog-12345"));
    }

    @Test
    void testAllHeadersHaveValidProperties() {
        List<HttpDevHeaderDoc> all = HttpDevKnowledgeBase.getAll();
        assertEquals(307, all.size());

        for (HttpDevHeaderDoc doc : all) {
            assertNotNull(doc.name(), "Name must not be null");
            assertFalse(doc.name().isBlank(), "Name must not be blank");
            assertNotNull(doc.category(), "Category must not be null for " + doc.name());
            assertNotNull(doc.summary(), "Summary must not be null for " + doc.name());
            assertFalse(doc.summary().isBlank(), "Summary must not be blank for " + doc.name());
            assertNotNull(doc.explanation(), "Explanation must not be null for " + doc.name());
            assertFalse(doc.explanation().isBlank(), "Explanation must not be blank for " + doc.name());
            assertNotNull(doc.referenceUrl(), "Reference URL must not be null for " + doc.name());
            assertTrue(doc.referenceUrl().startsWith("https://http.dev/"), "Reference URL must start with https://http.dev/ for " + doc.name());
        }
    }
}
