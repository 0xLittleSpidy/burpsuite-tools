// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import com.littlespidy.quickhelper.model.ExtensionItem_littlespidy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionCatalogServiceTest_littlespidy {

    private ExtensionCatalogService_littlespidy service;

    @BeforeEach
    void setUp() {
        service = new ExtensionCatalogService_littlespidy();
    }

    @Test
    void testCatalogCompleteness() {
        List<ExtensionItem_littlespidy> items = service.getCatalog();
        assertNotNull(items);
        assertTrue(items.size() >= 21, "Catalog should have at least 21 extensions");
        assertEquals(items.size(), service.getExtensionCount());
    }

    @Test
    void testItemPropertiesValidity() {
        for (ExtensionItem_littlespidy item : service.getCatalog()) {
            assertNotNull(item.getId(), "Extension ID should not be null");
            assertFalse(item.getId().isBlank(), "Extension ID should not be blank");

            assertNotNull(item.getName(), "Name should not be null for " + item.getId());
            assertFalse(item.getName().isBlank(), "Name should not be blank for " + item.getId());

            assertNotNull(item.getCategory(), "Category should not be null for " + item.getId());
            assertFalse(item.getCategory().isBlank(), "Category should not be blank for " + item.getId());

            assertNotNull(item.getJarFileName(), "JAR filename should not be null for " + item.getId());
            assertTrue(item.getJarFileName().endsWith(".jar"), "Filename must end with .jar for " + item.getId());

            assertNotNull(item.getDownloadUrl(), "Download URL should not be null for " + item.getId());
            assertTrue(item.getDownloadUrl().startsWith("https://github.com/0xLittleSpidy/burpsuite-tools/releases/download/"),
                    "Download URL should point to GitHub release: " + item.getDownloadUrl());

            assertTrue(item.isSelected(), "Default selection should be true for " + item.getId());
            assertEquals(ExtensionItem_littlespidy.Status.IDLE, item.getStatus());
        }
    }

    @Test
    void testCatalogContainsKeyExtensions() {
        List<String> ids = service.getCatalog().stream().map(ExtensionItem_littlespidy::getId).toList();
        assertTrue(ids.contains("javascript-inspector"));
        assertTrue(ids.contains("cache-header-inspector"));
        assertTrue(ids.contains("convert-post-to-get"));
        assertTrue(ids.contains("input-validation-fuzzer"));
        assertTrue(ids.contains("response-inspector"));
        assertTrue(ids.contains("jwt-comparator"));
        assertTrue(ids.contains("csp-inspector"));
        assertTrue(ids.contains("hsts-inspector"));
        assertTrue(ids.contains("upload-scanner"));
        assertTrue(ids.contains("session-inspector"));
        assertTrue(ids.contains("header-inspector"));
        assertTrue(ids.contains("activescan-session-keeper"));
        assertTrue(ids.contains("gwtmap"));
        assertTrue(ids.contains("request-smuggling-inspector"));
        assertTrue(ids.contains("sso-inspector"));
        assertTrue(ids.contains("api-inspector"));
        assertTrue(ids.contains("ng-auth-analyzer"));
        assertTrue(ids.contains("ng-sqlmap"));
        assertTrue(ids.contains("quick-helper"));
    }
}
