// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.activescansessionkeeper.config.CookieMode;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.engine.ScanSessionCoordinator;
import com.littlespidy.activescansessionkeeper.model.ScanActivityDataStore;
import com.littlespidy.activescansessionkeeper.model.ScanActivityEntry;
import com.littlespidy.activescansessionkeeper.ui.ActiveScanSessionKeeperTab;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class ActiveScanSessionKeeperPersistentStorageTest_littlespidy {

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

    private HttpRequestResponse createMockReqResp(String url, String reqStr, String respStr) {
        HttpService service = mock(HttpService.class);

        HttpRequest req = (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    if ("url".equals(method.getName())) return url;
                    if ("method".equals(method.getName())) return "GET";
                    if ("toByteArray".equals(method.getName())) {
                        ByteArray b = mock(ByteArray.class);
                        return b;
                    }
                    if ("httpService".equals(method.getName())) return service;
                    return null;
                }
        );

        HttpResponse resp = (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (proxy, method, args) -> {
                    if ("statusCode".equals(method.getName())) return (short) 200;
                    if ("toByteArray".equals(method.getName())) {
                        ByteArray b = mock(ByteArray.class);
                        return b;
                    }
                    return null;
                }
        );

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        return (HttpRequestResponse) Proxy.newProxyInstance(
                HttpRequestResponse.class.getClassLoader(),
                new Class<?>[]{HttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("request".equals(method.getName())) return req;
                    if ("response".equals(method.getName())) return resp;
                    if ("hasResponse".equals(method.getName())) return true;
                    if ("httpService".equals(method.getName())) return service;
                    return null;
                }
        );
    }

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        SessionKeeperConfig config = new SessionKeeperConfig();
        ScanActivityDataStore dataStore = new ScanActivityDataStore();
        ScanSessionCoordinator coordinator = new ScanSessionCoordinator(api, config, dataStore);

        ActiveScanSessionKeeperTab tab = new ActiveScanSessionKeeperTab(api, config, coordinator, dataStore);
        ActiveScanSessionKeeperPersistentStorageManager_littlespidy manager =
                new ActiveScanSessionKeeperPersistentStorageManager_littlespidy(api);
        manager.bindContext(tab, config, dataStore);
        tab.setStorageManager(manager);

        File sessionFile = tempDir.resolve("test_session_keeper_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        // Configure test settings
        config.setFullCookieHeader("sessionId=xyz123; token=abc456");
        config.setCookieMode(CookieMode.FULL_COOKIE_HEADER);
        config.setCheckBodyKeywords(true);
        config.setBodyKeywords("session_expired\nlogin_required");
        config.setStatusCodes("401, 403, 419");

        // Add a scan activity entry
        HttpRequestResponse mockReqResp = createMockReqResp("https://example.com/api/test", "GET /api/test HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n");
        ScanActivityEntry entry = new ScanActivityEntry(
                1,
                "Scanner",
                "GET",
                "example.com",
                "https://example.com/api/test",
                200,
                "PASSED",
                "Normal traffic",
                mockReqResp
        );
        dataStore.addEntry(entry);
        assertEquals(1, dataStore.getEntries().size());

        // Save session
        manager.saveSessionToFile(sessionFile);
        assertTrue(sessionFile.length() > 0);

        String jsonContent = Files.readString(sessionFile.toPath(), StandardCharsets.UTF_8);
        assertTrue(jsonContent.contains("sessionId=xyz123; token=abc456"));
        assertTrue(jsonContent.contains("session_expired"));

        // Reset state and restore
        config.setFullCookieHeader("");
        config.setBodyKeywords("");
        dataStore.clear();
        assertEquals(0, dataStore.getEntries().size());

        manager.openSessionFile(sessionFile);

        // Verify restoration
        assertEquals("sessionId=xyz123; token=abc456", config.getFullCookieHeader());
        assertEquals(CookieMode.FULL_COOKIE_HEADER, config.getCookieMode());
        assertTrue(config.getBodyKeywords().contains("session_expired"));
        assertEquals("401, 403, 419", config.getStatusCodes());
        assertEquals(1, dataStore.getEntries().size());
        assertEquals("https://example.com/api/test", dataStore.getEntries().get(0).getUrl());

        // Test offboard
        manager.offboardSession(tab);
        assertNull(manager.getActiveSessionFile());
        assertEquals("", config.getFullCookieHeader());
        assertEquals(0, dataStore.getEntries().size());
    }
}
