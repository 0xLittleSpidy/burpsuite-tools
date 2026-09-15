// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.knowledge;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Tests the offline embedded http.dev HTTP status code knowledge base.
 *
 * @author littlespidy
 */
class HttpDevStatusKnowledgeBaseTest {

    @Test
    void testLoadsAllStatuses() {
        int count = HttpDevStatusKnowledgeBase.totalCount();
        assertTrue(count >= 100, "Knowledge base should contain at least 100 status codes, found: " + count);
    }

    @Test
    void testStandardStatusSemantics() {
        // 200 OK
        HttpDevStatusDoc ok = HttpDevStatusKnowledgeBase.get(200);
        assertNotNull(ok, "200 OK should be found");
        assertEquals("OK", ok.name());
        assertEquals("2xx Success", ok.statusClass());
        assertTrue(ok.meaning().contains("succeeded"));
        assertTrue(ok.hasSpecifications());

        // 301 Moved Permanently
        HttpDevStatusDoc moved = HttpDevStatusKnowledgeBase.get(301);
        assertNotNull(moved);
        assertEquals("Moved Permanently", moved.name());
        assertEquals("3xx Redirection", moved.statusClass());

        // 404 Not Found
        HttpDevStatusDoc notFound = HttpDevStatusKnowledgeBase.get(404);
        assertNotNull(notFound);
        assertEquals("Not Found", notFound.name());
        assertEquals("4xx Client Error", notFound.statusClass());

        // 500 Internal Server Error
        HttpDevStatusDoc serverError = HttpDevStatusKnowledgeBase.get(500);
        assertNotNull(serverError);
        assertEquals("Internal Server Error", serverError.name());
        assertEquals("5xx Server Error", serverError.statusClass());
    }

    @Test
    void testVendorCodes() {
        // Cloudflare 522
        HttpDevStatusDoc cf522 = HttpDevStatusKnowledgeBase.get(522);
        assertNotNull(cf522, "Cloudflare 522 should be found");
        assertTrue(cf522.statusClass().contains("Vendor") || cf522.name().contains("Timed Out"));

        // Nginx 499 or 444
        HttpDevStatusDoc nginx444 = HttpDevStatusKnowledgeBase.get(444);
        assertNotNull(nginx444, "Nginx 444 should be found");
        assertEquals("No Response", nginx444.name());

        // 999 Request Denied (LinkedIn)
        HttpDevStatusDoc linkedin999 = HttpDevStatusKnowledgeBase.get(999);
        assertNotNull(linkedin999, "LinkedIn 999 should be found");
        assertEquals("Request Denied", linkedin999.name());
    }

    @Test
    void testStringLookup() {
        HttpDevStatusDoc doc = HttpDevStatusKnowledgeBase.get("404");
        assertNotNull(doc);
        assertEquals(404, doc.code());

        HttpDevStatusDoc byName = HttpDevStatusKnowledgeBase.get("Not Found");
        assertNotNull(byName);
        assertEquals(404, byName.code());
    }

    @Test
    void testUnknownCodeFallback() {
        HttpDevStatusDoc doc = HttpDevStatusKnowledgeBase.get(9999);
        assertNull(doc);
        assertFalse(HttpDevStatusKnowledgeBase.isKnown(9999));
        assertEquals("Status 9999", HttpDevStatusKnowledgeBase.getReasonPhrase(9999));
        assertEquals("Extended / Custom", HttpDevStatusKnowledgeBase.getStatusClass(9999));
    }

    @Test
    void testAllStatusesHaveValidProperties() {
        List<HttpDevStatusDoc> all = HttpDevStatusKnowledgeBase.getAll();
        for (HttpDevStatusDoc doc : all) {
            assertTrue(doc.code() > 0, "Code must be positive");
            assertNotNull(doc.name(), "Name must not be null for " + doc.code());
            assertFalse(doc.name().isBlank(), "Name must not be blank for " + doc.code());
            assertNotNull(doc.statusClass(), "StatusClass must not be null for " + doc.code());
            assertNotNull(doc.summary(), "Summary must not be null for " + doc.code());
            assertNotNull(doc.explanation(), "Explanation must not be null for " + doc.code());
            assertNotNull(doc.referenceUrl(), "Reference URL must not be null for " + doc.code());
            assertTrue(doc.referenceUrl().startsWith("https://http.dev/"), "URL must start with https://http.dev/ for " + doc.code());
        }
    }
}
