// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.persistence;

import com.littlespidy.sessionexpiration.cookiestore.model.CookieNameGroup;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieSource;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieStoreDataStore;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieValueRecord;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class SessionInspectorPersistenceTest {

    @BeforeEach
    public void setup() {
        SessionInspectorPersistence.clearPersistentFile();
    }

    @AfterEach
    public void teardown() {
        SessionInspectorPersistence.clearPersistentFile();
    }

    @Test
    public void testStoragePath() {
        Path path = SessionInspectorPersistence.getStoragePath();
        assertNotNull(path);
        assertTrue(path.toString().endsWith(".burp_session_inspector/session_inspector_store.json") ||
                   path.toString().contains(".burp_session_inspector"));
    }

    @Test
    public void testCookieStoreSaveAndLoadRoundtrip() {
        SessionDataStore sessionStore = new SessionDataStore();
        CookieStoreDataStore cookieStore = new CookieStoreDataStore();

        CookieValueRecord rec = new CookieValueRecord(
                1, "auth_token", CookieSource.RESPONSE, "secret12345",
                Set.of("example.com", "api.example.com"), 5,
                "Secure; HttpOnly; SameSite=Lax", null,
                "https://example.com/login", "POST", 200
        );
        cookieStore.restoreRecord("auth_token", CookieSource.RESPONSE, rec);
        cookieStore.setTotalMessagesProcessed(12);

        // Save synchronously
        SessionInspectorPersistence.saveSync(sessionStore, cookieStore, null);

        Path storagePath = SessionInspectorPersistence.getStoragePath();
        assertTrue(Files.exists(storagePath));

        // Create fresh stores to load into
        SessionDataStore restoredSessionStore = new SessionDataStore();
        CookieStoreDataStore restoredCookieStore = new CookieStoreDataStore();

        String summary = SessionInspectorPersistence.load(restoredSessionStore, restoredCookieStore, null, null);
        assertNotNull(summary);
        assertTrue(summary.contains("Restored 1 cookies"));

        Collection<CookieNameGroup> groups = restoredCookieStore.getAllGroups();
        assertEquals(1, groups.size());
        CookieNameGroup group = groups.iterator().next();
        assertEquals("auth_token", group.cookieName());
        assertEquals(1, group.uniqueValuesCount());

        var values = group.getValues();
        assertEquals(1, values.size());
        assertEquals("secret12345", values.get(0).value());
        assertEquals(5, values.get(0).occurrences());
        assertTrue(values.get(0).domains().contains("example.com"));
        assertEquals("Secure; HttpOnly; SameSite=Lax", values.get(0).attributes());
        assertEquals("https://example.com/login", values.get(0).sampleUrl());
        assertEquals(12, restoredCookieStore.totalMessagesProcessed());

        // Test clear
        boolean cleared = SessionInspectorPersistence.clearPersistentFile();
        assertTrue(cleared);
        assertFalse(Files.exists(storagePath));
    }

    @Test
    public void testCustomStorageDirectory() throws Exception {
        Path tempDir = Files.createTempDirectory("si_test_storage");
        try {
            SessionInspectorPersistence.setStorageDirectory(tempDir);
            Path expectedPath = tempDir.resolve(SessionInspectorPersistence.FILE_NAME);
            assertEquals(expectedPath, SessionInspectorPersistence.getStoragePath());

            SessionDataStore sessionStore = new SessionDataStore();
            CookieStoreDataStore cookieStore = new CookieStoreDataStore();
            SessionInspectorPersistence.saveSync(sessionStore, cookieStore, null);

            assertTrue(Files.exists(expectedPath));

            SessionDataStore restored = new SessionDataStore();
            String summary = SessionInspectorPersistence.load(restored, null, null, null);
            assertNotNull(summary);
            assertTrue(summary.contains("0 session tasks"));
        } finally {
            SessionInspectorPersistence.clearPersistentFile();
            // Reset to default
            SessionInspectorPersistence.setStorageDirectory(null);
            try {
                Files.deleteIfExists(tempDir.resolve(SessionInspectorPersistence.FILE_NAME));
                Files.deleteIfExists(tempDir);
            } catch (Exception ignored) {}
        }
    }

    @Test
    public void testCookieFinderTargetSerialization() {
        // Build JSON representation of cookie finder target
        String targetJson = "{" +
                "\"tabTitle\":\"Custom Target 1\"," +
                "\"url\":\"https://example.com/api/user\"," +
                "\"method\":\"GET\"," +
                "\"requestBase64\":\"" + java.util.Base64.getEncoder().encodeToString("GET /api/user HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes()) + "\"," +
                "\"customHeadersEnabled\":false," +
                "\"customHeadersText\":\"X-Custom-Token, X-Api-Key\"," +
                "\"rows\":[]" +
                "}";

        Object parsed = SimpleJson.parse(targetJson);
        assertTrue(parsed instanceof java.util.Map);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> parsedMap = (java.util.Map<String, Object>) parsed;

        assertEquals("Custom Target 1", SimpleJson.getString(parsedMap, "tabTitle", ""));
        assertEquals("https://example.com/api/user", SimpleJson.getString(parsedMap, "url", ""));
        assertEquals("GET", SimpleJson.getString(parsedMap, "method", ""));
        assertFalse(SimpleJson.getBoolean(parsedMap, "customHeadersEnabled", true));
        assertEquals("X-Custom-Token, X-Api-Key", SimpleJson.getString(parsedMap, "customHeadersText", ""));
    }
}
