// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SqlmapTaskOptionsTest {

    @Test
    public void testTargetResourceOptions() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/vuln.php?id=1");
        options.setDb("app_prod");
        options.setTbl("users");
        options.setCol("username,password_hash");
        options.setTamper("space2comment,between");

        // Verify Option Map for API
        Map<String, Object> map = options.toOptionMap();
        assertEquals("app_prod", map.get("db"));
        assertEquals("users", map.get("tbl"));
        assertEquals("username,password_hash", map.get("col"));
        assertEquals("space2comment,between", map.get("tamper"));

        // Verify CLI builder
        String cli = options.buildCommandLine();
        assertTrue(cli.contains("-D \"app_prod\""), "CLI should contain -D app_prod");
        assertTrue(cli.contains("-T \"users\""), "CLI should contain -T users");
        assertTrue(cli.contains("-C \"username,password_hash\""), "CLI should contain -C column");
        assertTrue(cli.contains("--tamper=\"space2comment,between\""), "CLI should contain tamper scripts");
        assertTrue(cli.contains("--proxy=\"http://127.0.0.1:8080\""), "CLI should contain default Burp proxy");
    }

    @Test
    public void testCopyConstructorPreservesTargetFields() {
        SqlmapTaskOptions src = new SqlmapTaskOptions();
        src.setDb("test_db");
        src.setTbl("test_tbl");
        src.setCol("test_col");
        src.setTamper("randomcase");

        SqlmapTaskOptions copy = new SqlmapTaskOptions(src);
        assertEquals("test_db", copy.getDb());
        assertEquals("test_tbl", copy.getTbl());
        assertEquals("test_col", copy.getCol());
        assertEquals("randomcase", copy.getTamper());
    }
}
