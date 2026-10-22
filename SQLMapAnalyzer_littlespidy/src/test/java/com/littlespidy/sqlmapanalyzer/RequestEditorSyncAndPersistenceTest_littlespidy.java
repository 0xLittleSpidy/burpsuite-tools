// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.persistence.ScanRequestSessionDto_littlespidy;
import com.littlespidy.sqlmapanalyzer.runner.ScanExecutionRecord;
import com.littlespidy.sqlmapanalyzer.runner.ScanRequestSession;
import com.littlespidy.sqlmapanalyzer.ui.runner.RequestScanTabPanel;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class RequestEditorSyncAndPersistenceTest_littlespidy {

    @Test
    public void testSessionUpdateRequestUpdatesFields() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://example.com/api/v1?id=1");
        byte[] initialRaw = "GET /api/v1?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(1, "GET", "http://example.com/api/v1?id=1", initialRaw, options);

        assertEquals("GET", session.getMethod());
        assertEquals("http://example.com/api/v1?id=1", session.getUrl());
        assertEquals("#1 GET /api/v1?id=1", session.getTabTitle());

        // Update the request with modified POST values
        byte[] updatedRaw = "POST /api/v2/user HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin'\"}".getBytes(StandardCharsets.UTF_8);
        session.updateRequest("POST", "http://example.com/api/v2/user", updatedRaw);

        assertEquals("POST", session.getMethod());
        assertEquals("http://example.com/api/v2/user", session.getUrl());
        assertArrayEquals(updatedRaw, session.getRawRequest());
        assertEquals("#1 POST /api/v2/user", session.getTabTitle());
    }

    @Test
    public void testRequestScanTabPanelSyncFromEditor() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/vuln.php?id=10");
        byte[] initialRaw = "GET /vuln.php?id=10 HTTP/1.1\r\nHost: target.local\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(2, "GET", "http://target.local/vuln.php?id=10", initialRaw, options);

        // Headless instantiation (api = null uses rawArea)
        RequestScanTabPanel tabPanel = new RequestScanTabPanel(null, session, null);
        assertNotNull(tabPanel.getRawAreaForTest());

        // User modifies request in the editor pane to a POST request with body
        String modifiedRequestText = "POST /api/search HTTP/1.1\r\n" +
                "Host: target.local\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "\r\n" +
                "query=test' OR 1=1--&cat=books";
        tabPanel.getRawAreaForTest().setText(modifiedRequestText);

        // Invoking getSession() triggers syncRequestEditorToSession()
        ScanRequestSession syncedSession = tabPanel.getSession();
        assertSame(session, syncedSession);

        assertEquals("POST", session.getMethod());
        assertEquals("http://target.local/api/search", session.getUrl());
        assertEquals("#2 POST /api/search", session.getTabTitle());

        // Check options in active execution
        ScanExecutionRecord active = session.getActiveExecution();
        assertNotNull(active);
        SqlmapTaskOptions activeOpts = active.getOptions();
        assertEquals("http://target.local/api/search", activeOpts.getUrl());
        assertEquals("POST", activeOpts.getMethod());
        assertEquals("query=test' OR 1=1--&cat=books", activeOpts.getData());
    }

    @Test
    public void testCliCommandGeneratedWithEditedRequest() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/search.php?q=abc");
        byte[] initialRaw = "GET /search.php?q=abc HTTP/1.1\r\nHost: target.local\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(3, "GET", "http://target.local/search.php?q=abc", initialRaw, options);

        RequestScanTabPanel tabPanel = new RequestScanTabPanel(null, session, null);

        // User edits the request to target a different endpoint with POST body
        String modifiedRequestText = "POST /api/orders HTTP/1.1\r\n" +
                "Host: target.local\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "{\"orderId\":999}";
        tabPanel.getRawAreaForTest().setText(modifiedRequestText);

        tabPanel.syncRequestEditorToSession();

        SqlmapTaskOptions activeOpts = session.getActiveExecution().getOptions();
        String cliCommand = activeOpts.buildCommandLine();

        assertTrue(cliCommand.contains("-u \"https://target.local/api/orders\""));
        assertTrue(cliCommand.contains("--force-ssl"));
        assertTrue(cliCommand.contains("--method=POST"));
        assertTrue(cliCommand.contains("--data=\"{\\\"orderId\\\":999}\""));
    }

    @Test
    public void testPersistenceSavesAndRestoresEditedRequest() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://example.org/old");
        byte[] oldRaw = "GET /old HTTP/1.1\r\nHost: example.org\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        ScanRequestSession session = new ScanRequestSession(5, "GET", "http://example.org/old", oldRaw, options);

        // Simulate user updating the request in the editor
        byte[] newRaw = ("PUT /rest/v1/items/42 HTTP/1.1\r\n" +
                "Host: api.example.org\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "{\"title\":\"updated item\"}").getBytes(StandardCharsets.UTF_8);

        session.updateRequest("PUT", "https://api.example.org/rest/v1/items/42", newRaw);
        session.getActiveExecution().getOptions().setUrl("https://api.example.org/rest/v1/items/42");
        session.getActiveExecution().getOptions().setMethod("PUT");
        session.getActiveExecution().getOptions().setData("{\"title\":\"updated item\"}");

        // Serialize to DTO (as done during session save)
        ScanRequestSessionDto_littlespidy dto = ScanRequestSessionDto_littlespidy.fromSession(session);
        assertNotNull(dto);
        assertEquals("PUT", dto.getMethod());
        assertEquals("https://api.example.org/rest/v1/items/42", dto.getUrl());
        assertFalse(dto.getRawRequestBase64().isEmpty());

        // Restore from DTO (as done during session restore)
        ScanRequestSession restored = dto.toSession();
        assertNotNull(restored);
        assertEquals(5, restored.getSessionId());
        assertEquals("PUT", restored.getMethod());
        assertEquals("https://api.example.org/rest/v1/items/42", restored.getUrl());
        assertArrayEquals(newRaw, restored.getRawRequest());
        assertEquals("#5 PUT /rest/v1/items/42", restored.getTabTitle());

        ScanExecutionRecord restoredRun = restored.getActiveExecution();
        assertNotNull(restoredRun);
        assertEquals("https://api.example.org/rest/v1/items/42", restoredRun.getOptions().getUrl());
        assertEquals("PUT", restoredRun.getOptions().getMethod());
        assertEquals("{\"title\":\"updated item\"}", restoredRun.getOptions().getData());
    }
}
