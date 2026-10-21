// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.model.DatabaseModel;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.parser.DirectoryScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class DirectoryScannerTest {

    private final DirectoryScanner scanner = new DirectoryScanner();

    @Test
    public void testScanFlatDirectoryStructure(@TempDir Path tempDir) throws IOException {
        // Flat structure: <tempDir>/db1/users.csv and <tempDir>/db2/products.csv
        File db1 = tempDir.resolve("db1").toFile();
        File db2 = tempDir.resolve("db2").toFile();
        assertTrue(db1.mkdirs());
        assertTrue(db2.mkdirs());

        try (FileWriter w = new FileWriter(new File(db1, "users.csv"))) {
            w.write("id,username,password\n1,admin,hash\n");
        }
        try (FileWriter w = new FileWriter(new File(db2, "products.csv"))) {
            w.write("id,name,price\n10,laptop,999\n");
        }

        SqlmapDataStore store = new SqlmapDataStore();
        AtomicInteger completedTables = new AtomicInteger(0);

        scanner.scanDirectory(tempDir.toFile(), store, new DirectoryScanner.ScanProgressListener() {
            @Override
            public void onProgress(String currentItem, int tableCount) {}

            @Override
            public void onComplete(int totalDatabases, int totalTables) {
                completedTables.set(totalTables);
            }

            @Override
            public void onError(String message, Throwable error) {
                fail("Scan failed: " + message);
            }
        });

        assertEquals(2, completedTables.get());
        assertEquals(2, store.getAllDatabases().size());
        assertNotNull(store.getDatabase("db1"));
        assertNotNull(store.getDatabase("db2"));
        assertEquals(1, store.getDatabase("db1").getTableCount());
        assertEquals(1, store.getDatabase("db2").getTableCount());
    }

    @Test
    public void testScanNestedSqlmapDumpStructure(@TempDir Path tempDir) throws IOException {
        // Nested structure: <tempDir>/target1.com/dump/production_db/accounts.csv
        File dumpDir = tempDir.resolve("target1.com/dump/production_db").toFile();
        assertTrue(dumpDir.mkdirs());

        try (FileWriter w = new FileWriter(new File(dumpDir, "accounts.csv"))) {
            w.write("account_id,balance,secret_token\n1,500,tok123\n2,1200,tok456\n");
        }

        SqlmapDataStore store = new SqlmapDataStore();
        scanner.scanDirectory(tempDir.toFile(), store, null);

        assertEquals(1, store.getAllDatabases().size());
        DatabaseModel db = store.getAllDatabases().get(0);
        assertEquals("production_db", db.getName());
        assertEquals("target1.com", db.getTargetHost());
        assertNotNull(db.getTable("accounts"));
        assertEquals(2, db.getTable("accounts").getRowCount());
        assertEquals(3, db.getTable("accounts").getColumnCount());
    }
}
