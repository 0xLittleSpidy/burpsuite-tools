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
}
