// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.storage;

import com.littlespidy.ssoinspector.model.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SSOPersistentStorageTest_littlespidy {

    @Test
    public void testSessionSaveAndOpen(@TempDir Path tempDir) throws Exception {
        OAuthDataStore store = new OAuthDataStore();
        SSOPersistentStorageManager_littlespidy manager = new SSOPersistentStorageManager_littlespidy(null);
        manager.bindDataStore(store);

        File sessionFile = tempDir.resolve("test_sso_session.json").toFile();
        manager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, manager.getActiveSessionFile());
        assertTrue(sessionFile.exists());

        OAuthRequestEntry entry = new OAuthRequestEntry(1, "12:00:00", null);
        entry.setFlowType(OAuthFlowType.AUTHORIZATION_CODE);

        OAuthParam param = new OAuthParam(
                "client_id",
                "app-12345",
                "app-12345",
                OAuthParam.ParamLocation.QUERY,
                "Client identifier",
                true,
                false
        );
        entry.setParameters(List.of(param));

        SSOAuditIssue issue = new SSOAuditIssue(
                "Missing State Parameter",
                IssueSeverity.HIGH,
                IssueConfidence.CERTAIN,
                "The state parameter is omitted, exposing the client to CSRF attacks.",
                "Implement a cryptographically random state parameter.",
                "RFC 6749 Section 10.12",
                null,
                false
        );
        entry.setIssues(List.of(issue));

        store.addEntry(entry);
        manager.saveNow();

        String json = Files.readString(sessionFile.toPath());
        assertTrue(json.contains("app-12345"));
        assertTrue(json.contains("Missing State Parameter"));
        assertTrue(json.contains("AUTHORIZATION_CODE"));

        // Open in a new manager
        OAuthDataStore restoredStore = new OAuthDataStore();
        SSOPersistentStorageManager_littlespidy manager2 = new SSOPersistentStorageManager_littlespidy(null);
        manager2.bindDataStore(restoredStore);

        manager2.openSessionFile(sessionFile);
        assertEquals(1, restoredStore.size());
        OAuthRequestEntry restored = restoredStore.getAllEntries().get(0);
        assertEquals("app-12345", restored.getClientId());
        assertEquals(OAuthFlowType.AUTHORIZATION_CODE, restored.getFlowType());
        assertEquals(1, restored.getParameters().size());
        assertEquals("client_id", restored.getParameters().get(0).getName());
        assertEquals(1, restored.getIssues().size());
        assertEquals("Missing State Parameter", restored.getIssues().get(0).getTitle());
        assertEquals(IssueSeverity.HIGH, restored.getIssues().get(0).getSeverity());

        // Test offboard
        manager2.offboardSession(null, null);
        assertNull(manager2.getActiveSessionFile());
        assertEquals(0, restoredStore.size());
    }
}
