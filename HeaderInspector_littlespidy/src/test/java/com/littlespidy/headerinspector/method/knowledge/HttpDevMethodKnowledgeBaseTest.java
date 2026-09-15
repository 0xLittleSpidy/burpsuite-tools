// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.knowledge;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Tests the offline embedded http.dev HTTP method knowledge base.
 *
 * @author littlespidy
 */
class HttpDevMethodKnowledgeBaseTest {

    @Test
    void testLoadsAllMethods() {
        int count = HttpDevMethodKnowledgeBase.totalCount();
        assertTrue(count >= 11, "Knowledge base should contain at least 11 core methods, found: " + count);
    }

    @Test
    void testStandardMethodsSemantics() {
        // GET
        HttpDevMethodDoc getDoc = HttpDevMethodKnowledgeBase.get("GET");
        assertNotNull(getDoc, "GET method should be found");
        assertTrue(getDoc.safe(), "GET should be safe");
        assertTrue(getDoc.idempotent(), "GET should be idempotent");
        assertTrue(getDoc.cacheable().equalsIgnoreCase("Yes"), "GET should be cacheable");
        assertTrue(getDoc.hasSpecifications());

        // POST
        HttpDevMethodDoc postDoc = HttpDevMethodKnowledgeBase.get("post");
        assertNotNull(postDoc, "Case-insensitive lookup for post should succeed");
        assertFalse(postDoc.safe(), "POST should be unsafe");
        assertFalse(postDoc.idempotent(), "POST should not be idempotent");
        assertTrue(postDoc.cacheable().toLowerCase().contains("conditional"), "POST should have conditional cacheability");

        // PUT
        HttpDevMethodDoc putDoc = HttpDevMethodKnowledgeBase.get("PUT");
        assertNotNull(putDoc);
        assertFalse(putDoc.safe(), "PUT should be unsafe");
        assertTrue(putDoc.idempotent(), "PUT should be idempotent");

        // DELETE
        HttpDevMethodDoc deleteDoc = HttpDevMethodKnowledgeBase.get("DELETE");
        assertNotNull(deleteDoc);
        assertFalse(deleteDoc.safe(), "DELETE should be unsafe");
        assertTrue(deleteDoc.idempotent(), "DELETE should be idempotent");
    }

    @Test
    void testWebDavMethods() {
        HttpDevMethodDoc propfind = HttpDevMethodKnowledgeBase.get("PROPFIND");
        assertNotNull(propfind, "PROPFIND WebDAV method should be present");
        assertTrue(propfind.safe(), "PROPFIND should be safe");
        assertTrue(propfind.idempotent(), "PROPFIND should be idempotent");

        HttpDevMethodDoc purge = HttpDevMethodKnowledgeBase.get("PURGE");
        assertNotNull(purge, "PURGE proxy method should be present");
        assertFalse(purge.safe());
        assertTrue(purge.idempotent());
    }

    @Test
    void testUnknownMethodFallback() {
        HttpDevMethodDoc unknown = HttpDevMethodKnowledgeBase.get("UNKNOWN_CUSTOM_METHOD");
        assertNull(unknown);
        assertFalse(HttpDevMethodKnowledgeBase.isKnown("UNKNOWN_CUSTOM_METHOD"));
        assertFalse(HttpDevMethodKnowledgeBase.isSafe("UNKNOWN_CUSTOM_METHOD"));
        assertFalse(HttpDevMethodKnowledgeBase.isIdempotent("UNKNOWN_CUSTOM_METHOD"));
        assertEquals("Unknown", HttpDevMethodKnowledgeBase.getCacheable("UNKNOWN_CUSTOM_METHOD"));
    }

    @Test
    void testAllMethodsHaveValidProperties() {
        List<HttpDevMethodDoc> all = HttpDevMethodKnowledgeBase.getAll();
        for (HttpDevMethodDoc doc : all) {
            assertNotNull(doc.name(), "Name must not be null");
            assertFalse(doc.name().isBlank(), "Name must not be blank");
            assertNotNull(doc.summary(), "Summary must not be null for " + doc.name());
            assertNotNull(doc.explanation(), "Explanation must not be null for " + doc.name());
            assertNotNull(doc.referenceUrl(), "Reference URL must not be null for " + doc.name());
            assertTrue(doc.referenceUrl().startsWith("https://http.dev/"), "URL must start with https://http.dev/ for " + doc.name());
        }
    }
}
