// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.uploadscanner.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.uploadscanner.model.StageType;
import com.littlespidy.uploadscanner.model.UploadEntry;
import com.littlespidy.uploadscanner.ui.UploadScannerTab;
import com.littlespidy.uploadscanner.ui.UploadSessionPanel;
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

public class UploadPersistentStorageTest_littlespidy {

    private static ByteArray mockByteArray(byte[] bytes) {
        byte[] safeBytes = (bytes != null) ? bytes : new byte[0];
        return (ByteArray) Proxy.newProxyInstance(
                ByteArray.class.getClassLoader(),
                new Class<?>[]{ByteArray.class},
                (proxy, method, args) -> {
                    if ("getBytes".equals(method.getName())) return safeBytes;
                    if ("length".equals(method.getName())) return safeBytes.length;
                    return null;
                }
        );
    }

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
                    if (method.getReturnType().equals(ByteArray.class)) return mockByteArray(new byte[0]);
                    if (method.getReturnType().isInterface()) return mock(method.getReturnType());
                    return null;
                }
        );
    }

    private static HttpRequest mockRequest(String method, String path, String body) {
        byte[] bytes = ("POST " + path + " HTTP/1.1\r\n\r\n" + body).getBytes(StandardCharsets.UTF_8);
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method1, args) -> {
                    String mName = method1.getName();
                    if ("method".equals(mName)) return method;
                    if ("path".equals(mName)) return path;
                    if ("toByteArray".equals(mName)) return mockByteArray(bytes);
                    if ("bodyToString".equals(mName)) return body;
                    if ("httpService".equals(mName)) return null;
                    if (method1.getReturnType().equals(String.class)) return "";
                    if (method1.getReturnType().equals(ByteArray.class)) return mockByteArray(bytes);
                    return null;
                }
        );
    }

    private static HttpResponse mockResponse(short status, String body) {
        byte[] bytes = ("HTTP/1.1 " + status + " OK\r\n\r\n" + body).getBytes(StandardCharsets.UTF_8);
        return (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (proxy, method, args) -> {
                    String mName = method.getName();
                    if ("statusCode".equals(mName)) return status;
                    if ("toByteArray".equals(mName)) return mockByteArray(bytes);
                    if ("bodyToString".equals(mName)) return body;
                    if (method.getReturnType().equals(ByteArray.class)) return mockByteArray(bytes);
                    return null;
                }
        );
    }

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);

        UploadPersistentStorageManager_littlespidy manager = new UploadPersistentStorageManager_littlespidy(api);
        UploadScannerTab tab = new UploadScannerTab(api);
        tab.setStorageManager(manager);
        manager.bindTab(tab);

        File sessionFile = tempDir.resolve("test_upload_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        HttpRequest req = mockRequest("POST", "/api/upload", "test_content");
        HttpResponse resp = mockResponse((short) 200, "OK");

        UploadSessionPanel sessionPanel = tab.addNewSessionTab(req, resp);
        assertNotNull(sessionPanel);
        assertEquals(1, tab.getActiveSessions().size());

        UploadEntry entry = new UploadEntry(
                1,
                StageType.UPLOAD,
                "POST",
                (short) 200,
                "shell.php",
                100,
                "https://example.com/api/upload",
                null,
                "canary_token_123",
                null,
                null
        );
        sessionPanel.getSessionLogPanel().getTableModel().addEntry(entry);

        // Save session
        manager.saveSessionToFile(sessionFile);
        assertTrue(sessionFile.length() > 0);

        String jsonContent = Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("canary_token_123"));
        assertTrue(jsonContent.contains("shell.php"));

        // Clear active tabs
        tab.clearAll();
        assertEquals(0, tab.getActiveSessions().size());

        // Restore session
        manager.openSessionFile(sessionFile);
        assertEquals(1, tab.getActiveSessions().size());

        UploadSessionPanel restoredSession = tab.getActiveSessions().get(0);
        assertEquals(1, restoredSession.getSessionLogPanel().getTableModel().getAllEntries().size());
        UploadEntry restoredEntry = restoredSession.getSessionLogPanel().getTableModel().getAllEntries().get(0);
        assertEquals("shell.php", restoredEntry.getPayloadName());
        assertEquals("canary_token_123", restoredEntry.getExtractedMarkerText());

        // Offboard session
        manager.startTemporarySession();
        assertNull(manager.getActiveSessionFile());
        assertEquals(0, tab.getActiveSessions().size());

        manager.shutdown();
    }
}
