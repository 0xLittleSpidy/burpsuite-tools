// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap;

import com.littlespidy.gwtmap.model.GWTDataStore;
import com.littlespidy.gwtmap.model.GWTMethod;
import com.littlespidy.gwtmap.model.GWTModuleInfo;
import com.littlespidy.gwtmap.model.GWTService;
import com.littlespidy.gwtmap.model.GwtHttpHistoryEntry;
import com.littlespidy.gwtmap.persistence.GWTMapPersistenceManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PersistenceTest {

    @Test
    public void testSaveAndLoadSession(@TempDir Path tempDir) {
        File dir = tempDir.toFile();

        // 1. Create data store
        GWTDataStore store = new GWTDataStore();
        GWTModuleInfo module = new GWTModuleInfo();
        module.setTargetUrl("https://example.com/app/app.nocache.js");
        module.setActivePermutation("ABCD1234EF5678");
        module.setBaseUrl("https://example.com/app/");
        module.setGwtVersion("2.8.2");
        store.setModuleInfo(module);

        GWTService service = new GWTService("userRpcService", "ABCD1234EF5678");
        store.addService(service);

        GWTMethod method = new GWTMethod(1, "getUserProfile", "UserServiceProxy", "UserService", "2", List.of("int", "java.lang.String"));
        method.setService(service);
        method.setFullEndpointUrl("https://example.com/app/userRpcService");
        method.setMethodRpcCall("7|0|4|https://example.com/app/|...");
        method.restoreProbeResult(null, null, 200, 42, "//OK[1,2,3]", 120, "Success");
        store.addMethod(method);

        // 2. Create history
        GwtHttpHistoryEntry entry = new GwtHttpHistoryEntry(
                1,
                "12:00:00",
                "PROBE",
                "POST",
                "https://example.com/app/userRpcService",
                200,
                42,
                120,
                null
        );
        store.addHttpHistoryEntry(entry);

        store.setRawCode("var uncleaned = 1;");
        store.setCleanedCode("function testDeobfuscated() { return true; }");

        String targetUrl = "https://example.com/app/app.nocache.js";
        String permUrl = "https://example.com/app/ABCD1234EF5678.cache.js";
        String customHeaders = "Cookie: session=xyz123\nAuthorization: Bearer test";

        // 3. Save session using GWTMapPersistenceManager
        GWTMapPersistenceManager manager = new GWTMapPersistenceManager(null);
        manager.setStorageDirectory(dir);

        boolean saved = manager.save(store, targetUrl, permUrl, customHeaders);
        assertTrue(saved, "save() should return true");

        File sessionFile = new File(dir, "gwtmap_session.json");
        assertTrue(sessionFile.exists(), "Session JSON file should exist");
        assertTrue(sessionFile.length() > 0, "Session JSON file should not be empty");

        // 4. Load session into a fresh data store
        GWTDataStore freshStore = new GWTDataStore();
        GWTMapPersistenceManager.SessionSnapshot loaded = manager.load(freshStore);
        assertNotNull(loaded, "Loaded snapshot should not be null");

        // 5. Verify assertions
        assertEquals(targetUrl, loaded.targetUrl);
        assertEquals(permUrl, loaded.permutationUrl);
        assertEquals(customHeaders, loaded.customHeaders);

        assertNotNull(freshStore.getModuleInfo());
        GWTModuleInfo loadedMod = freshStore.getModuleInfo();
        assertEquals("https://example.com/app/app.nocache.js", loadedMod.getTargetUrl());
        assertEquals("ABCD1234EF5678", loadedMod.getActivePermutation());
        assertEquals("https://example.com/app/", loadedMod.getBaseUrl());
        assertEquals("2.8.2", loadedMod.getGwtVersion());

        List<GWTService> services = freshStore.getAllServices();
        assertEquals(1, services.size());
        GWTService loadedSvc = services.get(0);
        assertEquals("userRpcService", loadedSvc.getServicePath());
        assertEquals("ABCD1234EF5678", loadedSvc.getStrongName());

        List<GWTMethod> methods = freshStore.getAllMethods();
        assertEquals(1, methods.size());
        GWTMethod loadedMethod = methods.get(0);
        assertEquals(1, loadedMethod.getId());
        assertEquals("getUserProfile", loadedMethod.getMethodName());
        assertEquals("UserServiceProxy", loadedMethod.getServiceProxy());
        assertEquals("UserService", loadedMethod.getRmtSvcIntName());
        assertEquals("2", loadedMethod.getParamCount());
        assertEquals(List.of("int", "java.lang.String"), loadedMethod.getMethodSignature());
        assertEquals("https://example.com/app/userRpcService", loadedMethod.getFullEndpointUrl());
        assertEquals("7|0|4|https://example.com/app/|...", loadedMethod.getMethodRpcCall());

        assertTrue(loadedMethod.isProbed());
        assertEquals(200, loadedMethod.getProbeStatusCode());
        assertEquals(42, loadedMethod.getProbeResponseLength());
        assertEquals("//OK[1,2,3]", loadedMethod.getProbeResponseBody());
        assertEquals(120, loadedMethod.getProbeResponseTimeMs());
        assertEquals("Success", loadedMethod.getProbeNotes());

        assertEquals(1, freshStore.getHttpHistory().size());
        GwtHttpHistoryEntry loadedEntry = freshStore.getHttpHistory().get(0);
        assertEquals(1, loadedEntry.getId());
        assertEquals("12:00:00", loadedEntry.getTimestamp());
        assertEquals("PROBE", loadedEntry.getType());
        assertEquals("POST", loadedEntry.getMethod());
        assertEquals("https://example.com/app/userRpcService", loadedEntry.getUrl());
        assertEquals(200, loadedEntry.getStatusCode());
        assertEquals(42, loadedEntry.getResponseLength());
        assertEquals(120, loadedEntry.getDurationMs());

        assertEquals("var uncleaned = 1;", freshStore.getRawCode());
        assertEquals("function testDeobfuscated() { return true; }", freshStore.getCleanedCode());
    }

    @SuppressWarnings("unchecked")
    private static <T> T mock(Class<T> type) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(
                type.getClassLoader(),
                new Class<?>[]{type},
                (proxy, method, args) -> {
                    if (method.getReturnType().equals(java.awt.Component.class) || method.getReturnType().equals(javax.swing.JComponent.class)) {
                        return new javax.swing.JPanel();
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
        burp.api.montoya.MontoyaApi api = mock(burp.api.montoya.MontoyaApi.class);

        GWTDataStore dataStore = new GWTDataStore();
        com.littlespidy.gwtmap.engine.GWTScanEngine engine = new com.littlespidy.gwtmap.engine.GWTScanEngine(api, dataStore);
        com.littlespidy.gwtmap.ui.GWTMapTab mainTab = new com.littlespidy.gwtmap.ui.GWTMapTab(api, dataStore, engine);
        GWTMapPersistenceManager manager = mainTab.getPersistenceManager();

        File sessionFile = tempDir.resolve("test_gwtmap_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        // Add a service
        GWTService svc = new GWTService("customService", "STRONG_HASH");
        dataStore.addService(svc);
        assertEquals(1, dataStore.getAllServices().size());

        // Save active session
        manager.saveActiveSession();
        assertTrue(sessionFile.length() > 0);

        String jsonContent = java.nio.file.Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("customService"));

        // Clear in-memory state
        mainTab.resetAll();
        assertEquals(0, dataStore.getAllServices().size());

        // Re-open session
        manager.openSessionFile(sessionFile);
        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertEquals(1, dataStore.getAllServices().size());

        // Test offboard session
        manager.offboardSession(mainTab);
        assertNull(manager.getActiveSessionFile());
        assertEquals(0, dataStore.getAllServices().size());

        manager.shutdown();
        engine.shutdown();
    }
}
