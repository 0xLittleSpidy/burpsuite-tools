// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.runner.ScanExecutionRecord;
import com.littlespidy.sqlmapanalyzer.runner.ScanRequestSession;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ScanExecutionLifecycleTest {

    @Test
    public void testCompletedScanCreatesNewExecutionRun() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://example.com/api?id=1");
        ScanRequestSession session = new ScanRequestSession(1, "GET", "http://example.com/api?id=1", new byte[0], options);

        assertEquals(1, session.getExecutions().size());
        ScanExecutionRecord run1 = session.getActiveExecution();
        assertNotNull(run1);
        assertEquals(1, run1.getExecutionNumber());

        // Simulate run1 completion
        run1.setStatus("COMPLETED");

        // When starting scan again on completed run, a new execution run should be created
        ScanExecutionRecord run2 = session.createNewExecution();
        assertEquals(2, session.getExecutions().size());
        assertEquals(2, run2.getExecutionNumber());
        assertEquals(run2, session.getActiveExecution());
        assertEquals("READY", run2.getStatus());
    }

    @Test
    public void testCancelledScanReusesExistingExecutionRun() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://example.com/api?id=1");
        ScanRequestSession session = new ScanRequestSession(1, "GET", "http://example.com/api?id=1", new byte[0], options);

        ScanExecutionRecord run1 = session.getActiveExecution();
        run1.setStatus("RUNNING");

        // User cancels scan
        run1.setCancelled(true);
        assertTrue(run1.isCancelled());
        assertEquals("CANCELLED", run1.getStatus());

        // Restarting cancelled scan reuses the same record
        run1.setCancelled(false);
        run1.setStatus("READY");
        assertEquals(1, session.getExecutions().size());
        assertEquals("READY", run1.getStatus());
        assertFalse(run1.isCancelled());
    }

    @Test
    public void testCustomTabTitleRenaming() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        ScanRequestSession session = new ScanRequestSession(4, "POST", "http://target.local/login", new byte[0], options);

        // Default naming: #4 POST /login
        assertEquals("#4 POST /login", session.getTabTitle());

        // Rename tab in-place
        session.setCustomTabTitle("Admin Auth Bypass");
        assertEquals("Admin Auth Bypass", session.getTabTitle());
        assertEquals("Admin Auth Bypass", session.getCustomTabTitle());

        // Clearing custom title falls back to default
        session.setCustomTabTitle("");
        assertEquals("#4 POST /login", session.getTabTitle());
    }

    @Test
    public void testSqlmapCommandAlwaysPresentInLogs() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/vuln?id=1");
        options.setDb("auth_db");
        options.setTbl("users");

        ScanExecutionRecord record = new ScanExecutionRecord(1, options);
        var logs = record.getLogs();
        assertFalse(logs.isEmpty());
        assertTrue(logs.get(0).getMessage().startsWith("SQLMAP Command: sqlmap -u \"https://target.local/vuln?id=1\""));
        assertTrue(logs.get(0).getMessage().contains("--force-ssl"));
        assertTrue(logs.get(0).getMessage().contains("-D \"auth_db\""));
        assertTrue(logs.get(0).getMessage().contains("-T \"users\""));

        // Simulate incoming API logs from sqlmapapi
        record.setLogs(java.util.List.of(
                new com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry("INFO", "10:00:01", "Testing connection to target"),
                new com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry("INFO", "10:00:02", "Heuristic test shows injectable")
        ));

        // Command line must remain index 0!
        var updatedLogs = record.getLogs();
        assertEquals(3, updatedLogs.size());
        assertTrue(updatedLogs.get(0).getMessage().startsWith("SQLMAP Command:"));
        assertEquals("Testing connection to target", updatedLogs.get(1).getMessage());
        assertEquals("Heuristic test shows injectable", updatedLogs.get(2).getMessage());
    }

    @Test
    public void testScanRequestSessionDtoRoundtrip() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("https://api.target.local/v1/user?id=100");
        options.setDbms("PostgreSQL");

        ScanRequestSession session = new ScanRequestSession(7, "GET", "https://api.target.local/v1/user?id=100", "GET /v1/user HTTP/1.1\r\n\r\n".getBytes(), options);
        session.setCustomTabTitle("User Profile Query");

        ScanExecutionRecord run = session.getActiveExecution();
        run.setStatus("VULNERABLE");
        run.setVulnerable(true);
        run.addFinding(new com.littlespidy.sqlmapanalyzer.api.model.SqlmapFinding(1, "id", "PostgreSQL", "Boolean-based blind", "AND 1=1", "Parameter 'id' is vulnerable"));

        // Convert to DTO and reconstruct
        com.littlespidy.sqlmapanalyzer.persistence.ScanRequestSessionDto_littlespidy dto =
                com.littlespidy.sqlmapanalyzer.persistence.ScanRequestSessionDto_littlespidy.fromSession(session);
        assertNotNull(dto);
        assertEquals(7, dto.getSessionId());
        assertEquals("User Profile Query", dto.getCustomTabTitle());
        assertEquals(1, dto.getExecutions().size());

        ScanRequestSession restored = dto.toSession();
        assertEquals(7, restored.getSessionId());
        assertEquals("User Profile Query", restored.getTabTitle());
        assertEquals("GET", restored.getMethod());
        assertEquals("https://api.target.local/v1/user?id=100", restored.getUrl());
        assertEquals(1, restored.getExecutions().size());
        assertEquals("VULNERABLE", restored.getActiveExecution().getStatus());
        assertTrue(restored.getActiveExecution().isVulnerable());
        assertEquals(1, restored.getActiveExecution().getFindings().size());
    }
}
