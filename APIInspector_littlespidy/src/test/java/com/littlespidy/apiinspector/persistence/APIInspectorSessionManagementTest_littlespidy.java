// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.AuthTestOutcome_littlespidy;
import com.littlespidy.apiinspector.model.AuthTestResult_littlespidy;
import com.littlespidy.apiinspector.model.AuthType_littlespidy;
import com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy;
import com.littlespidy.apiinspector.ui.AuthTestingTab_littlespidy.AuthTestRun_littlespidy;
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

    @Test
    public void testLoadSessionDoesNotOverwriteDataLoss(@TempDir Path tempDir) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        APIInspectorPersistenceManager_littlespidy manager = new APIInspectorPersistenceManager_littlespidy(api);
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(api);
        manager.setRootTab(rootTab);
        rootTab.setPersistenceManager(manager);

        // 1. Create a previous saved session file on disk (Session A)
        File sessionFileA = tempDir.resolve("session_a.json").toFile();
        manager.createNewSessionFile(sessionFileA);
        AuthProfile_littlespidy profileA = new AuthProfile_littlespidy("ProfileA", AuthType_littlespidy.BEARER_TOKEN);
        profileA.setBearerToken("token_alpha");
        rootTab.getAuthTestingTab().setProfiles(List.of(profileA));
        manager.saveActiveSession();

        String contentA = Files.readString(sessionFileA.toPath());
        assertTrue(contentA.contains("ProfileA"));
        assertFalse(contentA.contains("ProfileB"));

        // 2. Modify in-memory workspace to have Profile B (current data)
        AuthProfile_littlespidy profileB = new AuthProfile_littlespidy("ProfileB", AuthType_littlespidy.BASIC_AUTH);
        profileB.setBasicUsername("admin_beta");
        rootTab.getAuthTestingTab().setProfiles(List.of(profileB));

        // 3. User clicks load session to open Session A
        manager.openSessionFile(sessionFileA);

        // 4. Verify that sessionFileA on disk was NOT corrupted or overwritten by Profile B
        String contentAfterLoad = Files.readString(sessionFileA.toPath());
        assertTrue(contentAfterLoad.contains("ProfileA"), "Loaded session file must still contain ProfileA");
        assertFalse(contentAfterLoad.contains("ProfileB"), "Loaded session file must NOT be overwritten with current ProfileB data");

        // 5. Verify that the workspace accurately loaded ProfileA
        assertEquals(1, rootTab.getAuthTestingTab().getAllProfiles().size());
        assertEquals("ProfileA", rootTab.getAuthTestingTab().getAllProfiles().get(0).getName());

        manager.shutdown();
    }

    @Test
    public void testRunnerInformationSavedAndRestoredInSessionFile(@TempDir Path tempDir) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        APIInspectorPersistenceManager_littlespidy manager = new APIInspectorPersistenceManager_littlespidy(api);
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(api);
        manager.setRootTab(rootTab);
        rootTab.setPersistenceManager(manager);

        File sessionFile = tempDir.resolve("session_runners.json").toFile();
        manager.createNewSessionFile(sessionFile);

        // Configure profiles
        AuthProfile_littlespidy adminProfile = new AuthProfile_littlespidy("Admin", AuthType_littlespidy.BEARER_TOKEN);
        adminProfile.setRawHeaders("Authorization: Bearer admin-xyz");
        rootTab.getAuthTestingTab().setProfiles(List.of(adminProfile));

        // Create Run 1 results
        AuthTestResult_littlespidy r1 = new AuthTestResult_littlespidy();
        r1.setCollectionName("Petstore");
        r1.setMethod("GET");
        r1.setPath("/api/v1/user");
        r1.setProfileId(adminProfile.getId());
        r1.setProfileName(adminProfile.getName());
        r1.setAuthStatusCode(200);
        r1.setOutcome(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY);

        AuthTestRun_littlespidy run1 = new AuthTestRun_littlespidy("Runner 1", List.of(r1), null, null);

        // Create Run 2 results
        AuthTestResult_littlespidy r2 = new AuthTestResult_littlespidy();
        r2.setCollectionName("Petstore");
        r2.setMethod("POST");
        r2.setPath("/api/v1/order");
        r2.setProfileId(adminProfile.getId());
        r2.setProfileName(adminProfile.getName());
        r2.setAuthStatusCode(201);
        r2.setOutcome(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY);

        AuthTestRun_littlespidy run2 = new AuthTestRun_littlespidy("Runner 2", List.of(r2), null, null);

        // Set runners with run2 selected and counter = 3
        rootTab.getAuthTestingTab().setSavedRuns(List.of(run1, run2), run2.getId(), 3);
        assertEquals(2, rootTab.getAuthTestingTab().getSavedRuns().size());
        assertEquals(run2.getId(), rootTab.getAuthTestingTab().getSelectedRunnerId());
        assertEquals(3, rootTab.getAuthTestingTab().getRunnerCounter());

        // Save session
        manager.saveActiveSession();
        assertTrue(sessionFile.length() > 0);

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("authTestRuns"), "Session JSON must contain authTestRuns");
        assertTrue(json.contains("Runner 1"), "Session JSON must contain Runner 1");
        assertTrue(json.contains("Runner 2"), "Session JSON must contain Runner 2");
        assertTrue(json.contains(run2.getId()), "Session JSON must contain selectedRunnerId");
        assertTrue(json.contains("\"runnerCounter\": 3"), "Session JSON must contain runnerCounter 3");

        // Reset workspace
        rootTab.resetWorkspace();
        assertEquals(0, rootTab.getAuthTestingTab().getSavedRuns().size());
        assertNull(rootTab.getAuthTestingTab().getSelectedRunnerId());

        // Open session from disk
        manager.openSessionFile(sessionFile);

        // Verify restoration
        assertEquals(2, rootTab.getAuthTestingTab().getSavedRuns().size());
        assertEquals("Runner 1", rootTab.getAuthTestingTab().getSavedRuns().get(0).getName());
        assertEquals("Runner 2", rootTab.getAuthTestingTab().getSavedRuns().get(1).getName());
        assertEquals(run2.getId(), rootTab.getAuthTestingTab().getSelectedRunnerId(), "Active runner must be restored to Runner 2");
        assertEquals(3, rootTab.getAuthTestingTab().getRunnerCounter());
        assertEquals(1, rootTab.getAuthTestingTab().getAllResults().size());
        assertEquals("/api/v1/order", rootTab.getAuthTestingTab().getAllResults().get(0).getPath());

        manager.shutdown();
    }

    @Test
    public void testLegacySessionResultsLoadedIntoSynthesizedRunner(@TempDir Path tempDir) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        APIInspectorPersistenceManager_littlespidy manager = new APIInspectorPersistenceManager_littlespidy(api);
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(api);
        manager.setRootTab(rootTab);
        rootTab.setPersistenceManager(manager);

        File sessionFile = tempDir.resolve("legacy_session.json").toFile();

        // Write legacy JSON with only authTestResults and no authTestRuns
        String legacyJson = "{\n" +
                "  \"version\": 2,\n" +
                "  \"savedAt\": " + System.currentTimeMillis() + ",\n" +
                "  \"tabs\": [],\n" +
                "  \"authTestResults\": [\n" +
                "    {\n" +
                "      \"id\": \"res-legacy-1\",\n" +
                "      \"method\": \"GET\",\n" +
                "      \"path\": \"/api/legacy\",\n" +
                "      \"profileName\": \"Admin\",\n" +
                "      \"authStatusCode\": 200,\n" +
                "      \"outcome\": \"AUTHENTICATED_ONLY\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        Files.writeString(sessionFile.toPath(), legacyJson);

        manager.openSessionFile(sessionFile);

        // Should be automatically wrapped into Runner 1
        assertEquals(1, rootTab.getAuthTestingTab().getSavedRuns().size(), "Legacy results must synthesize a default runner");
        assertEquals("Runner 1", rootTab.getAuthTestingTab().getSavedRuns().get(0).getName());
        assertEquals(1, rootTab.getAuthTestingTab().getAllResults().size());
        assertEquals("/api/legacy", rootTab.getAuthTestingTab().getAllResults().get(0).getPath());

        manager.shutdown();
    }

    @Test
    public void testProfileRawHeadersAndUnauthSavedInSessionFile(@TempDir Path tempDir) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        APIInspectorPersistenceManager_littlespidy manager = new APIInspectorPersistenceManager_littlespidy(api);
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(api);
        manager.setRootTab(rootTab);
        rootTab.setPersistenceManager(manager);

        File sessionFile = tempDir.resolve("profile_headers_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        AuthProfile_littlespidy p1 = new AuthProfile_littlespidy("CustomAuth", AuthType_littlespidy.CUSTOM_HEADER);
        p1.setRawHeaders("Authorization: Bearer token123\nCookie: session=abc");
        p1.setUnauthenticated(false);

        AuthProfile_littlespidy p2 = new AuthProfile_littlespidy("UnauthStrip", AuthType_littlespidy.CUSTOM_HEADER);
        p2.setRawHeaders("Authorization:\nCookie:");
        p2.setUnauthenticated(true);

        rootTab.getAuthTestingTab().setProfiles(List.of(p1, p2));
        manager.saveActiveSession();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("token123"));
        assertTrue(json.contains("UnauthStrip"));
        assertTrue(json.contains("\"unauthenticated\": true"));

        rootTab.resetWorkspace();
        assertEquals(0, rootTab.getAuthTestingTab().getAllProfiles().size());

        manager.openSessionFile(sessionFile);
        List<AuthProfile_littlespidy> restored = rootTab.getAuthTestingTab().getAllProfiles();
        assertEquals(2, restored.size());

        AuthProfile_littlespidy rp1 = restored.get(0);
        assertFalse(rp1.isUnauthenticated());
        assertTrue(rp1.getRawHeaders().contains("token123"));

        AuthProfile_littlespidy rp2 = restored.get(1);
        assertTrue(rp2.isUnauthenticated());
        assertTrue(rp2.getRawHeaders().contains("Cookie:"));

        manager.shutdown();
    }
}
