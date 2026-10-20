// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.storage;

import com.littlespidy.cspinspector.model.CSPDataStore;
import com.littlespidy.cspinspector.model.CSPEntry;
import com.littlespidy.cspinspector.model.CSPParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class CSPPersistentStorageTest_littlespidy {

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        CSPDataStore store = new CSPDataStore();
        CSPPersistentStorageManager_littlespidy manager = new CSPPersistentStorageManager_littlespidy(null);
        manager.bindDataStore(store);

        File sessionFile = tempDir.resolve("test_csp_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        String policy = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com";
        Map<String, List<String>> parsed = CSPParser.parsePolicy(policy);

        CSPEntry entry = new CSPEntry(
                1,
                "https://target.com/dashboard",
                "target.com",
                "/dashboard",
                "GET",
                200,
                "text/html",
                policy,
                "",
                "",
                "",
                parsed,
                null,
                null,
                ZonedDateTime.now()
        );
        store.addEntry(entry);
        manager.saveNow();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("target.com"));
        assertTrue(json.contains("script-src"));

        // Open in a new manager
        CSPDataStore restoredStore = new CSPDataStore();
        CSPPersistentStorageManager_littlespidy manager2 = new CSPPersistentStorageManager_littlespidy(null);
        manager2.bindDataStore(restoredStore);

        manager2.openSessionFile(sessionFile);
        assertEquals(1, restoredStore.size());
        CSPEntry restored = restoredStore.getEntries().get(0);
        assertEquals("https://target.com/dashboard", restored.url());
        assertEquals(policy, restored.cspHeader());
        assertTrue(restored.parsedDirectives().containsKey("script-src"));

        // Test offboard
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, restoredStore.size());
    }
}
