// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiClient;
import com.littlespidy.sqlmapanalyzer.api.SqlmapApiConfig;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapFinding;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapScanStatus;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SqlmapApiClientTest {

    private final Gson gson = new Gson();

    @Test
    public void testSqlmapTaskOptionsSerialization() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/vuln.php?id=1");
        options.setMethod("GET");
        options.setTestParameter("id");
        options.setLevel(3);
        options.setRisk(2);
        options.setTechnique("BEU");
        options.setDbms("MySQL");
        options.setTamper("space2comment");
        options.setThreads(4);
        options.setDumpTable(true);
        options.setGetBanner(true);

        Map<String, Object> map = options.toOptionMap();
        assertNotNull(map);
        assertEquals("http://target.local/vuln.php?id=1", map.get("url"));
        assertEquals("GET", map.get("method"));
        assertEquals("id", map.get("testParameter"));
        assertEquals(3, map.get("level"));
        assertEquals(2, map.get("risk"));
        assertEquals("BEU", map.get("technique"));
        assertEquals("MySQL", map.get("dbms"));
        assertEquals("space2comment", map.get("tamper"));
        assertEquals(4, map.get("threads"));
        assertEquals("true", map.get("dumpTable"));

        String cli = options.buildCommandLine();
        assertTrue(cli.contains("-u \"https://target.local/vuln.php?id=1\""));
        assertTrue(cli.contains("--force-ssl"));
        assertTrue(cli.contains("-p \"id\""));
        assertTrue(cli.contains("--level=3"));
        assertTrue(cli.contains("--risk=2"));
        assertTrue(cli.contains("--technique=BEU"));
        assertTrue(cli.contains("--dbms=\"MySQL\""));
        assertTrue(cli.contains("--tamper=\"space2comment\""));
        assertTrue(cli.contains("--threads=4"));
        assertTrue(cli.contains("--dump"));
    }

    @Test
    public void testSqlmapLogEntryParsing() {
        String json = "{\"level\": \"INFO\", \"time\": \"21:15:30\", \"message\": \"testing connection to the target URL\"}";
        SqlmapLogEntry entry = gson.fromJson(json, SqlmapLogEntry.class);

        assertNotNull(entry);
        assertEquals("INFO", entry.getLevel());
        assertEquals("21:15:30", entry.getTime());
        assertEquals("testing connection to the target URL", entry.getMessage());
        assertEquals("[INFO] 21:15:30 - testing connection to the target URL", entry.getFormatted());
    }

    @Test
    public void testSqlmapScanStatus() {
        SqlmapScanStatus running = new SqlmapScanStatus(true, "running", 0);
        assertTrue(running.isSuccess());
        assertTrue(running.isRunning());
        assertFalse(running.isTerminated());

        SqlmapScanStatus terminated = new SqlmapScanStatus(true, "terminated", 0);
        assertTrue(terminated.isSuccess());
        assertFalse(terminated.isRunning());
        assertTrue(terminated.isTerminated());
    }

    @Test
    public void testGetScanDataWithJsonNullDoesNotThrow() throws Exception {
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/scan/test-task/data", exchange -> {
            String jsonResponse = "{\"success\": true, \"data\": [" +
                    "{\"type\": 3, \"value\": null}," +
                    "{\"type\": 4, \"value\": null}," +
                    "{\"type\": 7, \"value\": null}," +
                    "{\"type\": 1, \"value\": [{\"dbms\": null, \"parameter\": \"id\", \"place\": null, \"data\": {\"1\": {\"title\": null, \"payload\": null}}}]}" +
                    "]}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        try {
            SqlmapApiConfig config = new SqlmapApiConfig();
            config.setHost("127.0.0.1");
            config.setPort(server.getAddress().getPort());
            config.setUsername("");
            config.setPassword("");

            SqlmapApiClient client = new SqlmapApiClient(config);
            List<SqlmapFinding> findings = client.getScanData("test-task");
            assertNotNull(findings);
            // Verify findings parsed without throwing JsonNull UnsupportedOperationException
            assertFalse(findings.isEmpty());
        } finally {
            server.stop(0);
        }
    }
}
