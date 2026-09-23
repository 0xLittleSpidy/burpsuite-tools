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
}
