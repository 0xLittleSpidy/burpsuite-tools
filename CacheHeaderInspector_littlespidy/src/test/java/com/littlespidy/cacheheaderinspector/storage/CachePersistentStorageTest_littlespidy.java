// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.storage;

import com.littlespidy.cacheheaderinspector.model.CacheDataStore;
import com.littlespidy.cacheheaderinspector.model.CacheEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.*;

public class CachePersistentStorageTest_littlespidy {

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        CacheDataStore store = new CacheDataStore();
        CachePersistentStorageManager_littlespidy manager = new CachePersistentStorageManager_littlespidy(null);
        manager.bindDataStore(store);

        File sessionFile = tempDir.resolve("test_cache_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        // Add an entry
        CacheEntry entry = new CacheEntry(
                1,
                "https://api.target.com/v1/user",
                "api.target.com",
                "/v1/user",
                "GET",
                200,
                "application/json",
                "max-age=3600, public",
                "no-cache",
                "",
                "120",
                "\"etag123\"",
                "",
                "Accept-Encoding",
                "HIT",
                "2",
                "public",
                "",
                "HIT",
                null,
                null,
                ZonedDateTime.now()
        );
        store.addEntry(entry);
        manager.saveNow();

        String jsonContent = Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("api.target.com"));
        assertTrue(jsonContent.contains("max-age=3600, public"));

        // Open in a new manager & store
        CacheDataStore restoredStore = new CacheDataStore();
        CachePersistentStorageManager_littlespidy manager2 = new CachePersistentStorageManager_littlespidy(null);
        manager2.bindDataStore(restoredStore);

        manager2.openSessionFile(sessionFile);
        assertEquals(1, restoredStore.size());
        CacheEntry restored = restoredStore.getEntries().get(0);
        assertEquals("https://api.target.com/v1/user", restored.url());
        assertEquals("max-age=3600, public", restored.cacheControl());
        assertEquals(200, restored.statusCode());

        // Test offboarding
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, restoredStore.size());
    }
}
