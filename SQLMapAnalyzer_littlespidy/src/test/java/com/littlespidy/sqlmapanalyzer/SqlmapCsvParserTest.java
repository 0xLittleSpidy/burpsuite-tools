// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.model.TableData;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;
import com.littlespidy.sqlmapanalyzer.parser.SqlmapCsvParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SqlmapCsvParserTest {

    private final SqlmapCsvParser parser = new SqlmapCsvParser();

    @Test
    public void testParseMetadataAndFullTable(@TempDir Path tempDir) throws IOException {
        File csvFile = tempDir.resolve("users.csv").toFile();
        try (FileWriter writer = new FileWriter(csvFile)) {
            writer.write("id,username,password_hash,email\n");
            writer.write("1,admin,5f4dcc3b5aa765d61d8327deb882cf99,admin@example.com\n");
            writer.write("2,alice,098f6bcd4621d373cade4e832627b4f6,alice@example.com\n");
            writer.write("3,bob,e10adc3949ba59abbe56e057f20f883e,bob@example.com\n");
        }

        TableMetadata meta = parser.parseMetadata("localhost", "app_db", "users", csvFile);
        assertNotNull(meta);
        assertEquals("app_db", meta.getDatabaseName());
        assertEquals("users", meta.getTableName());
        assertEquals(4, meta.getColumnCount());
        assertEquals(3, meta.getRowCount());
        assertTrue(meta.getColumnNames().contains("username"));
        assertTrue(meta.getColumnNames().contains("password_hash"));

        TableData data = parser.parseFullTable(csvFile);
        assertNotNull(data);
        assertEquals(4, data.getColumnCount());
        assertEquals(3, data.getRowCount());
        assertEquals("admin", data.getRows().get(0).get(1));
        assertEquals("bob@example.com", data.getRows().get(2).get(3));
    }

    @Test
    public void testMultilineAndQuotedCsv(@TempDir Path tempDir) throws IOException {
        File csvFile = tempDir.resolve("logs.csv").toFile();
        try (FileWriter writer = new FileWriter(csvFile)) {
            writer.write("id,message,created_at\n");
            writer.write("1,\"Line 1\nLine 2 with, comma\",2026-01-01\n");
            writer.write("2,\"Normal message\",2026-01-02\n");
        }

        TableData data = parser.parseFullTable(csvFile);
        assertEquals(2, data.getRowCount());
        assertEquals("Line 1\nLine 2 with, comma", data.getRows().get(0).get(1));
    }

    @Test
    public void testExportToCsv(@TempDir Path tempDir) throws IOException {
        File exportFile = tempDir.resolve("exported.csv").toFile();
        List<String> headers = List.of("col1", "col2");
        List<List<String>> rows = List.of(
                List.of("val1", "val2"),
                List.of("val3", "val4")
        );

        parser.exportToCsv(exportFile, headers, rows);
        assertTrue(exportFile.exists());

        TableData reloaded = parser.parseFullTable(exportFile);
        assertEquals(2, reloaded.getColumnCount());
        assertEquals(2, reloaded.getRowCount());
        assertEquals("val1", reloaded.getRows().get(0).get(0));
    }
}
