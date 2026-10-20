// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.inputvalidationfuzzer.storage;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.inputvalidationfuzzer.model.*;
import com.littlespidy.inputvalidationfuzzer.ui.InputValidationFuzzerTab;
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

import static org.junit.jupiter.api.Assertions.*;

public class FuzzerPersistentStorageTest_littlespidy {

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
        FuzzerConfig config = new FuzzerConfig();

        FuzzerPersistentStorageManager_littlespidy manager = new FuzzerPersistentStorageManager_littlespidy(api);
        InputValidationFuzzerTab tab = new InputValidationFuzzerTab(api, config, manager);
        manager.bindTab(tab);

        File sessionFile = tempDir.resolve("test_fuzzer_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        TrafficCandidate candidate = new TrafficCandidate(
                1,
                "POST",
                "https://target.com/api/login",
                "target.com",
                "/api/login",
                200,
                512,
                "application/json",
                2,
                List.of("username", "password"),
                true,
                "Bearer",
                "POST|https://target.com/api/login",
                null,
                null,
                ZonedDateTime.now()
        );

        tab.getTrafficSweepPanel().setCandidates(List.of(candidate));

        // Create an attack session
        ConfiguredHeader header = new ConfiguredHeader("Authorization", "Bearer test-token");
        FuzzResult result = new FuzzResult(
                1,
                "username",
                "JSON",
                "SQL Single Quote",
                "'",
                200,
                512,
                500,
                1024,
                "text/html",
                "5xx Server Error",
                "High",
                "Internal Server Error leaking SQL syntax",
                null,
                null,
                null,
                null,
                null,
                ZonedDateTime.now()
        );

        tab.restoreSessionTab("Attack Login", List.of(candidate), List.of(header), List.of(result));
        manager.saveNow();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("target.com"));
        assertTrue(json.contains("SQL Single Quote"));
        assertTrue(json.contains("Bearer test-token"));

        // Open in a new manager and tab
        FuzzerPersistentStorageManager_littlespidy manager2 = new FuzzerPersistentStorageManager_littlespidy(api);
        InputValidationFuzzerTab tab2 = new InputValidationFuzzerTab(api, config, manager2);
        manager2.bindTab(tab2);

        manager2.openSessionFile(sessionFile);
        assertEquals(1, tab2.getTrafficSweepPanel().getCandidates().size());
        assertEquals("https://target.com/api/login", tab2.getTrafficSweepPanel().getCandidates().get(0).url());
        assertEquals(1, tab2.getActiveSessions().size());
        assertEquals("Attack Login", tab2.getActiveSessions().get(0).getSessionTitle());
        assertEquals(1, tab2.getActiveSessions().get(0).getSessionHeaders().size());
        assertEquals("Authorization", tab2.getActiveSessions().get(0).getSessionHeaders().get(0).name());
        assertEquals(1, tab2.getActiveSessions().get(0).getResults().size());
        assertEquals("SQL Single Quote", tab2.getActiveSessions().get(0).getResults().get(0).payloadName());

        // Test offboard
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, tab2.getTrafficSweepPanel().getCandidates().size());
        assertEquals(0, tab2.getActiveSessions().size());
    }
}
