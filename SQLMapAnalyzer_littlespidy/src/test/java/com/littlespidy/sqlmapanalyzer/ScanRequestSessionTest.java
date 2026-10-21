// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.runner.ScanExecutionRecord;
import com.littlespidy.sqlmapanalyzer.runner.ScanRequestSession;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ScanRequestSessionTest {

    @Test
    public void testSessionInitializationAndTitle() {
        SqlmapTaskOptions opt = new SqlmapTaskOptions();
        opt.setUrl("https://api.example.com/v1/users?page=1");
        opt.setMethod("GET");

        ScanRequestSession session = new ScanRequestSession(1, "GET", "https://api.example.com/v1/users?page=1", new byte[0], opt);

        assertEquals(1, session.getSessionId());
        assertEquals("GET", session.getMethod());
        assertEquals(1, session.getExecutions().size());
        assertEquals(0, session.getActiveExecutionIndex());

        ScanExecutionRecord firstRun = session.getActiveExecution();
        assertNotNull(firstRun);
        assertEquals(1, firstRun.getExecutionNumber());
        assertEquals("READY", firstRun.getStatus());

        String title = session.getTabTitle();
        assertTrue(title.startsWith("#1 GET"));
        assertTrue(title.contains("/v1/users"));
    }

    @Test
    public void testMultipleExecutionRuns() {
        SqlmapTaskOptions opt = new SqlmapTaskOptions();
        opt.setUrl("https://api.example.com/login");
        opt.setMethod("POST");
        opt.setLevel(2);

        ScanRequestSession session = new ScanRequestSession(5, "POST", "https://api.example.com/login", new byte[0], opt);
        assertEquals(1, session.getExecutions().size());

        // Create Run #2
        ScanExecutionRecord run2 = session.createNewExecution();
        assertNotNull(run2);
        assertEquals(2, run2.getExecutionNumber());
        assertEquals(2, session.getExecutions().size());
        assertEquals(1, session.getActiveExecutionIndex());
        assertEquals(2, run2.getOptions().getLevel()); // Inherited previous level

        // Modifying run 2 should not affect run 1
        run2.getOptions().setLevel(5);
        assertEquals(5, session.getExecutions().get(1).getOptions().getLevel());
        assertEquals(2, session.getExecutions().get(0).getOptions().getLevel());

        // Delete test
        boolean deleted = session.deleteExecution(0);
        assertTrue(deleted);
        assertEquals(1, session.getExecutions().size());

        // Cannot delete last execution
        boolean cantDelete = session.deleteExecution(0);
        assertFalse(cantDelete);
        assertEquals(1, session.getExecutions().size());
    }
}
