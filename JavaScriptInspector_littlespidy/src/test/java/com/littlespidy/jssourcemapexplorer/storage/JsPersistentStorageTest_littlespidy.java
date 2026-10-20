// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.storage;

import com.littlespidy.jssourcemapexplorer.model.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class JsPersistentStorageTest_littlespidy {

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        JsDataStore store = new JsDataStore();
        JsPersistentStorageManager_littlespidy manager = new JsPersistentStorageManager_littlespidy(null);
        manager.bindDataStore(store);

        File sessionFile = tempDir.resolve("test_js_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        JsFileEntry entry = new JsFileEntry(
                1,
                "https://target.com/static/js/main.chunk.js",
                "target.com",
                "/static/js/main.chunk.js",
                200,
                1024,
                true,
                "1st Party",
                PassiveMapStatus.COMMENT_FOUND,
                "https://target.com/static/js/main.chunk.js.map",
                null,
                null,
                ZonedDateTime.now()
        );
        entry.setFramework("React");
        entry.setActiveProbeStatus(ActiveProbeStatus.PASS);

        DiscoveredSecret sec = new DiscoveredSecret(
                "main.chunk.js",
                "JS File",
                "AWS Access Key",
                "AKIAIOSFODNN7EXAMPLE",
                "High",
                4.2,
                "High [Firm]",
                "Regex",
                12,
                100,
                120,
                "const key = 'AKIAIOSFODNN7EXAMPLE';"
        );

        DiscoveredEndpoint ep = new DiscoveredEndpoint(
                "main.chunk.js",
                "JS File",
                "/api/v2/users",
                "GET",
                25,
                200,
                213,
                "fetch('/api/v2/users')",
                "Path Extractor"
        );

        entry.setJsReconFindings(List.of(sec), List.of(ep));

        // Add unpacked project
        UnpackedProject project = new UnpackedProject("https://target.com/static/js/main.chunk.js.map");
        UnpackedSourceFile srcFile = new UnpackedSourceFile(
                "src/App.tsx",
                "App.tsx",
                "export default function App() { return <div>Test</div>; }",
                1,
                55,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of()
        );
        project.addFile(srcFile);
        entry.setUnpackedProject(project);

        store.addEntry(entry);
        manager.saveNow();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("main.chunk.js"));
        assertTrue(json.contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(json.contains("/api/v2/users"));
        assertTrue(json.contains("App.tsx"));

        // Open in a new manager
        JsDataStore restoredStore = new JsDataStore();
        JsPersistentStorageManager_littlespidy manager2 = new JsPersistentStorageManager_littlespidy(null);
        manager2.bindDataStore(restoredStore);

        manager2.openSessionFile(sessionFile);
        assertEquals(1, restoredStore.size());
        JsFileEntry restored = restoredStore.getEntries().get(0);
        assertEquals("https://target.com/static/js/main.chunk.js", restored.getUrl());
        assertEquals("React", restored.getFramework());
        assertEquals(PassiveMapStatus.COMMENT_FOUND, restored.getPassiveMapStatus());
        assertEquals(ActiveProbeStatus.PASS, restored.getActiveProbeStatus());
        assertEquals(1, restored.getJsSecrets().size());
        assertEquals("AKIAIOSFODNN7EXAMPLE", restored.getJsSecrets().get(0).secretValue());
        assertEquals(1, restored.getJsEndpoints().size());
        assertEquals("/api/v2/users", restored.getJsEndpoints().get(0).endpoint());
        assertTrue(restored.isUnpacked());
        assertNotNull(restored.getUnpackedProject());
        assertEquals(1, restored.getUnpackedProject().getTotalFiles());
        assertNotNull(restored.getUnpackedProject().getFile("src/App.tsx"));

        // Test offboard
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, restoredStore.size());
    }
}
