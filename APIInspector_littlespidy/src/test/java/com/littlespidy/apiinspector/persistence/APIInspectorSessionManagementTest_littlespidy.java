// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.AuthType_littlespidy;
import com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class APIInspectorSessionManagementTest_littlespidy {

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
    public void testSessionManagementLifecycle(@TempDir Path tempDir) throws Exception {
        System.out.println("[TEST] Step 1: Mock API");
        MontoyaApi api = mock(MontoyaApi.class);
        System.out.println("[TEST] Step 2: PersistenceManager");
        APIInspectorPersistenceManager_littlespidy manager = new APIInspectorPersistenceManager_littlespidy(api);
        System.out.println("[TEST] Step 3: RootTab");
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(api);
        System.out.println("[TEST] Step 4: setPersistenceManager");
        manager.setRootTab(rootTab);
        rootTab.setPersistenceManager(manager);

        System.out.println("[TEST] Step 5: createNewSessionFile");
        File sessionFile = tempDir.resolve("test_api_inspector_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        System.out.println("[TEST] Step 6: add profile");
        AuthProfile_littlespidy profile = new AuthProfile_littlespidy("TestProfile", AuthType_littlespidy.BEARER_TOKEN);
        profile.setBearerToken("eyJhbGciOi...");
        rootTab.getAuthTestingTab().setProfiles(List.of(profile));
        assertEquals(1, rootTab.getAuthTestingTab().getAllProfiles().size());

        System.out.println("[TEST] Step 7: saveActiveSession");
        manager.saveActiveSession();
        assertTrue(sessionFile.length() > 0);

        String jsonContent = Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("TestProfile"));

        System.out.println("[TEST] Step 8: resetWorkspace");
        rootTab.resetWorkspace();
        assertEquals(0, rootTab.getAuthTestingTab().getAllProfiles().size());

        System.out.println("[TEST] Step 9: openSessionFile");
        manager.openSessionFile(sessionFile);
        assertEquals(sessionFile, manager.getActiveSessionFile());

        System.out.println("[TEST] Step 10: offboardSession");
        manager.offboardSession(rootTab);
        assertNull(manager.getActiveSessionFile());
        assertEquals(0, rootTab.getAuthTestingTab().getAllProfiles().size());

        System.out.println("[TEST] Step 11: shutdown");
        manager.shutdown();
        System.out.println("[TEST] Done!");
    }
}
