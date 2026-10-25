// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.storage;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.payloadinjector.model.*;
import com.littlespidy.payloadinjector.ui.PayloadInjectorTab;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PayloadInjectorPersistentStorageTest_littlespidy {

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
        burp.api.montoya.extension.Extension extensionMock = (burp.api.montoya.extension.Extension) Proxy.newProxyInstance(
                burp.api.montoya.extension.Extension.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.extension.Extension.class},
                (proxy, method, args) -> {
                    if ("filename".equals(method.getName())) {
                        return tempDir.resolve("dummy.jar").toString();
                    }
                    if (method.getReturnType().equals(String.class)) return "";
                    if (method.getReturnType().isInterface()) return mock(method.getReturnType());
                    return null;
                }
        );

        MontoyaApi api = (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> {
                    if ("extension".equals(method.getName())) {
                        return extensionMock;
                    }
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

        Map<String, ParamPayloadStore> paramStores = new LinkedHashMap<>();
        ParamPayloadStore xssStore = new ParamPayloadStore(api, "xss_payloads.json");
        paramStores.put("XSS", xssStore);

        SmugglingPayloadStore smugglingStore = new SmugglingPayloadStore(api);
        FilePathStore_littlespidy linuxFilePathStore = new FilePathStore_littlespidy(api, "linux_file_paths_littlespidy.json", "Linux");
        FilePathStore_littlespidy windowsFilePathStore = new FilePathStore_littlespidy(api, "windows_file_paths_littlespidy.json", "Windows");
        InjectionSettings settings = new InjectionSettings();

        PayloadInjectorTab tab = new PayloadInjectorTab(paramStores, smugglingStore, linuxFilePathStore, windowsFilePathStore, settings);
        PayloadInjectorPersistentStorageManager_littlespidy manager = new PayloadInjectorPersistentStorageManager_littlespidy(api);
        manager.bindContext(tab, paramStores, smugglingStore, linuxFilePathStore, windowsFilePathStore, settings);
        tab.setStorageManager(manager);

        File sessionFile = tempDir.resolve("test_payload_injector_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        // Modify settings
        settings.setTargetCookieParams(true);
        settings.setInjectionMode(InjectionSettings.InjectionMode.APPEND);

        // Add a test payload to XSS
        ParamPayloadEntry customXss = new ParamPayloadEntry(
                "custom-xss-1",
                "Custom Test Alert",
                "<script>alert(1337)</script>",
                "Testing persistent storage for custom payload",
                true,
                "Manual",
                "N/A",
                "All"
        );
        xssStore.addEntry(customXss);

        // Add a test file path
        FilePathEntry_littlespidy customPath = new FilePathEntry_littlespidy(
                "custom-path-1",
                "/custom/etc/secret.conf",
                "Secret",
                "Test path",
                "Linux",
                true,
                "Manual",
                "N/A"
        );
        linuxFilePathStore.addEntry(customPath);

        // Save session
        manager.saveSessionToFile(sessionFile);
        assertTrue(sessionFile.length() > 0);

        String jsonContent = Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("Custom Test Alert"));
        assertTrue(jsonContent.contains("<script>alert(1337)</script>"));
        assertTrue(jsonContent.contains("/custom/etc/secret.conf"));

        // Reset settings and clear stores
        settings.setTargetCookieParams(false);
        settings.setInjectionMode(InjectionSettings.InjectionMode.REPLACE);
        xssStore.replaceEntries(java.util.Collections.emptyList());
        linuxFilePathStore.replaceEntries(java.util.Collections.emptyList());

        assertEquals(0, xssStore.getEntries().size());
        assertEquals(0, linuxFilePathStore.getEntries().size());
        assertFalse(settings.isTargetCookieParams());

        // Restore session
        manager.openSessionFile(sessionFile);
        assertTrue(settings.isTargetCookieParams());
        assertEquals(InjectionSettings.InjectionMode.APPEND, settings.getInjectionMode());

        assertTrue(xssStore.getEntries().stream().anyMatch(e -> "Custom Test Alert".equals(e.getName())));
        assertTrue(linuxFilePathStore.getEntries().stream().anyMatch(e -> "/custom/etc/secret.conf".equals(e.getPath())));

        // Offboard session
        manager.startTemporarySession();
        assertNull(manager.getActiveSessionFile());

        manager.shutdown();
    }
}
