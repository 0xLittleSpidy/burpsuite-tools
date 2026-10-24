// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop;

import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.AuditSeverity_littlespidy;
import com.littlespidy.graphqlcop.model.SessionData_littlespidy;
import com.littlespidy.graphqlcop.model.WorkspaceSessionData_littlespidy;
import com.littlespidy.graphqlcop.persistence.SessionManager_littlespidy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

public class SessionManagerTest_littlespidy {

    @TempDir
    Path tempDir;

    private SessionManager_littlespidy sessionManager;
    private WorkspaceSessionData_littlespidy testWorkspace;
    private AtomicBoolean resetCalled;

    @BeforeEach
    public void setUp() {
        testWorkspace = new WorkspaceSessionData_littlespidy();
        SessionData_littlespidy tab = new SessionData_littlespidy("id-1", "#1 POST /graphql", "https://api.target.com/graphql");
        tab.setCustomHeaders("Authorization: Bearer token123");

        AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                "f1",
                AuditProbeType_littlespidy.INTROSPECTION,
                AuditSeverity_littlespidy.HIGH,
                "Introspection Query Enabled",
                "Full schema exposed",
                "Disable introspection",
                "Information disclosure",
                "https://api.target.com/graphql",
                "",
                ""
        );
        tab.setFindings(Collections.singletonList(finding));
        testWorkspace.setEndpointTabs(Collections.singletonList(tab));

        resetCalled = new AtomicBoolean(false);

        SessionManager_littlespidy.SessionPersistenceCallback callback = new SessionManager_littlespidy.SessionPersistenceCallback() {
            @Override
            public WorkspaceSessionData_littlespidy exportCurrentSession() {
                return testWorkspace;
            }

            @Override
            public void importSession(WorkspaceSessionData_littlespidy data) {
                testWorkspace = data;
            }

            @Override
            public void resetSession() {
                resetCalled.set(true);
                testWorkspace = new WorkspaceSessionData_littlespidy();
            }
        };

        sessionManager = new SessionManager_littlespidy(null, callback);
    }

    @Test
    public void testCreateNewSessionAndSave() throws Exception {
        File sessionFile = tempDir.resolve("test_session.json").toFile();
        sessionManager.createNewSessionFile(sessionFile);

        assertEquals(sessionFile, sessionManager.getActiveSessionFile());
        assertTrue(sessionFile.exists(), "Session file should exist on disk");

        String content = Files.readString(sessionFile.toPath());
        assertNotNull(content);
        assertTrue(content.contains("savedTimestamp"));
    }

    @Test
    public void testOpenSessionFile() throws Exception {
        File sessionFile = tempDir.resolve("test_open.json").toFile();
        sessionManager.createNewSessionFile(sessionFile);

        // Modify testWorkspace and save
        SessionData_littlespidy tab = new SessionData_littlespidy("id-2", "#2 POST /api", "https://api2.target.com/graphql");
        testWorkspace.setEndpointTabs(Collections.singletonList(tab));
        sessionManager.markDirty();
        sessionManager.saveSync();

        // Create new session manager to simulate reopening
        WorkspaceSessionData_littlespidy freshWorkspace = new WorkspaceSessionData_littlespidy();
        SessionManager_littlespidy reopenManager = new SessionManager_littlespidy(null, new SessionManager_littlespidy.SessionPersistenceCallback() {
            @Override
            public WorkspaceSessionData_littlespidy exportCurrentSession() {
                return freshWorkspace;
            }

            @Override
            public void importSession(WorkspaceSessionData_littlespidy data) {
                freshWorkspace.setEndpointTabs(data.getEndpointTabs());
            }

            @Override
            public void resetSession() {}
        });

        reopenManager.openSessionFile(sessionFile);
        assertEquals(sessionFile, reopenManager.getActiveSessionFile());
        assertFalse(freshWorkspace.getEndpointTabs().isEmpty());
        assertEquals("#2 POST /api", freshWorkspace.getEndpointTabs().get(0).getTabTitle());
    }

    @Test
    public void testOffboardSession() {
        File sessionFile = tempDir.resolve("test_offboard.json").toFile();
        sessionManager.createNewSessionFile(sessionFile);
        assertEquals(sessionFile, sessionManager.getActiveSessionFile());

        sessionManager.offboardSession(null);
        assertNull(sessionManager.getActiveSessionFile());
        assertTrue(resetCalled.get(), "Reset callback should be invoked on offboard");
    }
}
