// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.storage;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.requestsmugglinginspector.model.PayloadEntry;
import com.littlespidy.requestsmugglinginspector.model.PayloadStore;
import com.littlespidy.requestsmugglinginspector.ui.PayloadsTab;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SmugglingPersistentStorageTest_littlespidy {

    @SuppressWarnings("unchecked")
    private static <T> T mock(Class<T> type) {
        return (T) Proxy.newProxyInstance(
                type.getClassLoader(),
                new Class<?>[]{type},
                (proxy, method, args) -> {
                    if (method.getReturnType().equals(Component.class) || method.getReturnType().equals(JComponent.class)) {
                        return new JPanel();
                    }
                    if (method.getReturnType().equals(String.class)) return "";
                    if (method.getReturnType().equals(boolean.class)) return false;
                    if (method.getReturnType().equals(int.class)) return 0;
                    if (method.getReturnType().isInterface()) return mock(method.getReturnType());
                    return null;
                }
        );
    }

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);

        PayloadStore store = new PayloadStore(api);
        PayloadsTab tab = new PayloadsTab(store);
        SmugglingPersistentStorageManager_littlespidy manager = new SmugglingPersistentStorageManager_littlespidy(api);
        manager.bindTab(tab);
        manager.bindStore(store);
        tab.setStorageManager(manager);

        File sessionFile = tempDir.resolve("test_smuggling_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        PayloadEntry entry = new PayloadEntry(
                "CL.TE Test Vector",
                "Testing CL.TE smuggling via Transfer-Encoding chunked",
                Map.of("Transfer-Encoding", "chunked", "Content-Length", "4"),
                "0\\r\\n\\r\\nSMUGGLED"
        );
        store.addEntry(entry);
        tab.refreshTable();

        // Save session
        manager.saveSessionToFile(sessionFile);
        assertTrue(sessionFile.length() > 0);

        String jsonContent = Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("CL.TE Test Vector"));
        assertTrue(jsonContent.contains("SMUGGLED"));

        // Clear store
        store.clear();
        tab.refreshTable();
        assertEquals(0, store.getEntries().size());

        // Restore session
        manager.openSessionFile(sessionFile);
        assertEquals(1, store.getEntries().size());
        PayloadEntry restored = store.getEntries().get(0);
        assertEquals("CL.TE Test Vector", restored.getName());
        assertEquals("0\\r\\n\\r\\nSMUGGLED", restored.getBody());
        assertEquals("chunked", restored.getHeaders().get("Transfer-Encoding"));

        // Offboard session
        manager.startTemporarySession();
        assertNull(manager.getActiveSessionFile());

        manager.shutdown();
    }
}
