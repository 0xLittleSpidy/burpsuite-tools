// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.storage;

import com.littlespidy.headerinspector.cache.model.CacheDataStore;
import com.littlespidy.headerinspector.cache.model.CacheEntry;
import com.littlespidy.headerinspector.collector.model.HeaderCollectorDataStore;
import com.littlespidy.headerinspector.csp.model.CSPDataStore;
import com.littlespidy.headerinspector.csp.model.CSPEntry;
import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.hsts.model.HSTSEntry;
import com.littlespidy.headerinspector.method.model.MethodCollectorDataStore;
import com.littlespidy.headerinspector.status.model.StatusCollectorDataStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class HeaderPersistentStorageTest_littlespidy {

    @Test
    public void testHeaderSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        HeaderCollectorDataStore headerStore = new HeaderCollectorDataStore();
        MethodCollectorDataStore methodStore = new MethodCollectorDataStore();
        StatusCollectorDataStore statusStore = new StatusCollectorDataStore();
        CacheDataStore cacheStore = new CacheDataStore();
        CSPDataStore cspStore = new CSPDataStore();
        HSTSDataStore hstsStore = new HSTSDataStore();

        HeaderPersistentStorageManager_littlespidy manager = new HeaderPersistentStorageManager_littlespidy(null);
        manager.bindDataStores(headerStore, methodStore, statusStore, cacheStore, cspStore, hstsStore);

        File sessionFile = tempDir.resolve("test_header_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        // Add Cache Entry
        cacheStore.addEntry(new CacheEntry(
                1, "https://api.example.com/test", "api.example.com", "/test", "GET",
                200, "application/json", "max-age=600", "", "", "", "", "", "",
                "", "", "", "", "", null, null, ZonedDateTime.now()
        ));

        // Add CSP Entry
        cspStore.addEntry(new CSPEntry(
                1, "https://api.example.com/test", "api.example.com", "/test", "GET",
                200, "application/json", "default-src 'none'", "", "", "",
                Collections.emptyMap(), null, null, ZonedDateTime.now()
        ));

        // Add HSTS Entry
        hstsStore.addEntries(List.of(new HSTSEntry(
                1, "https://api.example.com/test", "api.example.com", "/test", "GET",
                200, "application/json", "max-age=31536000; includeSubDomains; preload", 31536000, true,
                true, null, null, ZonedDateTime.now()
        )));

        manager.saveNow();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("api.example.com"));
        assertTrue(json.contains("max-age=600"));
        assertTrue(json.contains("default-src 'none'"));
        assertTrue(json.contains("31536000"));

        // Restore in fresh stores
        HeaderCollectorDataStore headerStore2 = new HeaderCollectorDataStore();
        MethodCollectorDataStore methodStore2 = new MethodCollectorDataStore();
        StatusCollectorDataStore statusStore2 = new StatusCollectorDataStore();
        CacheDataStore cacheStore2 = new CacheDataStore();
        CSPDataStore cspStore2 = new CSPDataStore();
        HSTSDataStore hstsStore2 = new HSTSDataStore();

        HeaderPersistentStorageManager_littlespidy manager2 = new HeaderPersistentStorageManager_littlespidy(null);
        manager2.bindDataStores(headerStore2, methodStore2, statusStore2, cacheStore2, cspStore2, hstsStore2);

        manager2.openSessionFile(sessionFile);

        assertEquals(1, cacheStore2.size());
        assertEquals(1, cspStore2.size());
        assertEquals(1, hstsStore2.size());
        assertEquals("max-age=600", cacheStore2.getEntries().get(0).cacheControl());
        assertEquals("default-src 'none'", cspStore2.getEntries().get(0).cspHeader());
        assertEquals(31536000, hstsStore2.getEntries().get(0).maxAge());

        // Test offboarding
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, cacheStore2.size());
        assertEquals(0, cspStore2.size());
        assertEquals(0, hstsStore2.size());
    }
}
