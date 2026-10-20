// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.storage;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieSource;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieStoreDataStore;
import com.littlespidy.sessionexpiration.cookiestore.model.CookieValueRecord;
import com.littlespidy.sessionexpiration.engine.SessionTimerEngine;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import com.littlespidy.sessionexpiration.ui.SessionExpirationTab;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class SessionInspectorPersistentStorageTest_littlespidy {

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
        SessionDataStore sessionStore = new SessionDataStore();
        SessionTimerEngine timerEngine = new SessionTimerEngine(api);

        SessionExpirationTab tab = new SessionExpirationTab(api, sessionStore, timerEngine);
        SessionInspectorPersistentStorageManager_littlespidy manager =
                new SessionInspectorPersistentStorageManager_littlespidy(api);
        manager.bindContext(tab, sessionStore, tab.getCookieStoreDataStore(), tab.getCookieFinderTab());
        tab.setStorageManager(manager);

        File sessionFile = tempDir.resolve("test_session_inspector_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        // Add cookie to CookieStore
        CookieStoreDataStore cookieStore = tab.getCookieStoreDataStore();
        CookieValueRecord rec = new CookieValueRecord(
                1, "sid_test", CookieSource.RESPONSE, "secret12345",
                Set.of("example.com"), 3,
                "Secure; HttpOnly", null,
                "https://example.com/login", "POST", 200
        );
        cookieStore.restoreRecord("sid_test", CookieSource.RESPONSE, rec);
        cookieStore.setTotalMessagesProcessed(5);

        // Save session
        manager.saveSessionToFile(sessionFile);
        assertTrue(sessionFile.length() > 0);

        String jsonContent = Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("sid_test"));
        assertTrue(jsonContent.contains("secret12345"));

        // Clear in-memory state
        cookieStore.clear();
        assertEquals(0, cookieStore.getAllGroups().size());

        // Re-open session
        manager.openSessionFile(sessionFile);
        assertEquals(1, cookieStore.getAllGroups().size());
        assertEquals("sid_test", cookieStore.getAllGroups().iterator().next().cookieName());

        // Test offboard
        manager.offboardSession(tab);
        assertNull(manager.getActiveSessionFile());
        assertEquals(0, cookieStore.getAllGroups().size());

        manager.shutdown();
        tab.cleanup();
    }
}
