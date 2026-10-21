// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapScanStatus;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import org.junit.jupiter.api.Test;

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
        assertTrue(cli.contains("-u \"http://target.local/vuln.php?id=1\""));
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
}
