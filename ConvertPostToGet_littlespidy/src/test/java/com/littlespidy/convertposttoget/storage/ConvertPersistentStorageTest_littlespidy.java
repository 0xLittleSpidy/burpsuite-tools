// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.storage;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.convertposttoget.model.*;
import com.littlespidy.convertposttoget.ui.ConvertPostToGetTab;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class ConvertPersistentStorageTest_littlespidy {

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
        ConvertPostToGetConfig config = new ConvertPostToGetConfig();

        ConvertPersistentStorageManager_littlespidy manager = new ConvertPersistentStorageManager_littlespidy(api);
        ConvertPostToGetTab tab = new ConvertPostToGetTab(api, config, manager);
        manager.bindTab(tab);

        File sessionFile = tempDir.resolve("test_convert_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        PostCandidate candidate = new PostCandidate(
                1,
                "POST",
                "https://target.com/api/update-profile",
                "target.com",
                "/api/update-profile",
                200,
                256,
                "application/json",
                2,
                List.of("email", "role"),
                Set.of("JSON"),
                true,
                "Cookie",
                "POST|https://target.com/api/update-profile",
                null,
                null,
                ZonedDateTime.now()
        );

        tab.getTrafficSweepPanel().setCandidates(List.of(candidate));

        // Create an attack session
        ConfiguredHeader header = new ConfiguredHeader("X-Requested-With", "XMLHttpRequest");
        ConversionResult result = new ConversionResult(
                1,
                "POST",
                "https://target.com/api/update-profile",
                "target.com",
                "/api/update-profile",
                200,
                256,
                200,
                256,
                "application/json",
                "Method Permitted / CSRF Potential",
                "High",
                "Server accepted GET and executed profile update with same response length",
                null,
                null,
                null,
                null,
                null,
                ZonedDateTime.now()
        );

        tab.restoreSessionTab("Attack Profile", List.of(candidate), List.of(header), List.of(result));
        manager.saveNow();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("target.com"));
        assertTrue(json.contains("/api/update-profile"));
        assertTrue(json.contains("Method Permitted / CSRF Potential"));
        assertTrue(json.contains("X-Requested-With"));

        // Open in a new manager and tab
        ConvertPersistentStorageManager_littlespidy manager2 = new ConvertPersistentStorageManager_littlespidy(api);
        ConvertPostToGetTab tab2 = new ConvertPostToGetTab(api, config, manager2);
        manager2.bindTab(tab2);

        manager2.openSessionFile(sessionFile);
        assertEquals(1, tab2.getTrafficSweepPanel().getCandidates().size());
        assertEquals("https://target.com/api/update-profile", tab2.getTrafficSweepPanel().getCandidates().get(0).url());
        assertEquals(1, tab2.getActiveSessions().size());
        assertEquals("Attack Profile", tab2.getActiveSessions().get(0).getSessionTitle());
        assertEquals(1, tab2.getActiveSessions().get(0).getSessionHeaders().size());
        assertEquals("X-Requested-With", tab2.getActiveSessions().get(0).getSessionHeaders().get(0).name());
        assertEquals(1, tab2.getActiveSessions().get(0).getResults().size());
        assertEquals("Method Permitted / CSRF Potential", tab2.getActiveSessions().get(0).getResults().get(0).signal());

        // Test offboard
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, tab2.getTrafficSweepPanel().getCandidates().size());
        assertEquals(0, tab2.getActiveSessions().size());
    }
}
