// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.storage;

import com.littlespidy.hstsinspector.model.HSTSDataStore;
import com.littlespidy.hstsinspector.model.HSTSEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.*;

public class HSTSPersistentStorageTest_littlespidy {

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        HSTSDataStore store = new HSTSDataStore();
        HSTSPersistentStorageManager_littlespidy manager = new HSTSPersistentStorageManager_littlespidy(null);
        manager.bindDataStore(store);

        File sessionFile = tempDir.resolve("test_hsts_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        HSTSEntry entry = new HSTSEntry(
                1,
                "https://target.com/api/v1/auth",
                "target.com",
                "/api/v1/auth",
                "POST",
                200,
                "application/json",
                "max-age=31536000; includeSubDomains; preload",
                31536000L,
                true,
                true,
                null,
                null,
                ZonedDateTime.now()
        );
        store.addEntries(java.util.List.of(entry));
        manager.saveNow();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("target.com"));
        assertTrue(json.contains("31536000"));
        assertTrue(json.contains("includeSubDomains"));

        // Open in a new manager
        HSTSDataStore restoredStore = new HSTSDataStore();
        HSTSPersistentStorageManager_littlespidy manager2 = new HSTSPersistentStorageManager_littlespidy(null);
        manager2.bindDataStore(restoredStore);

        manager2.openSessionFile(sessionFile);
        assertEquals(1, restoredStore.size());
        HSTSEntry restored = restoredStore.getEntries().get(0);
        assertEquals("https://target.com/api/v1/auth", restored.url());
        assertEquals("max-age=31536000; includeSubDomains; preload", restored.hstsHeader());
        assertEquals(31536000L, restored.maxAge());
        assertTrue(restored.includeSubDomains());
        assertTrue(restored.preload());

        // Test offboard
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, restoredStore.size());
    }
}
