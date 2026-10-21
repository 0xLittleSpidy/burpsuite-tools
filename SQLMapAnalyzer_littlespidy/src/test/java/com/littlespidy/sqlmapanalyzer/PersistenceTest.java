// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.model.ColumnOccurrence;
import com.littlespidy.sqlmapanalyzer.model.DatabaseModel;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;
import com.littlespidy.sqlmapanalyzer.persistence.SQLMapPersistenceManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PersistenceTest {

    @Test
    public void testColumnGatheringAndKeywordSearch() {
        SqlmapDataStore store = new SqlmapDataStore();

        DatabaseModel db1 = new DatabaseModel("db_users", "hostA");
        db1.addTable(new TableMetadata("hostA", "db_users", "tbl_auth", null, List.of("id", "username", "password_hash", "auth_token"), 10));
        db1.addTable(new TableMetadata("hostA", "db_users", "tbl_profiles", null, List.of("id", "username", "email", "phone_number"), 10));

        DatabaseModel db2 = new DatabaseModel("db_billing", "hostA");
        db2.addTable(new TableMetadata("hostA", "db_billing", "tbl_invoices", null, List.of("id", "username", "card_number", "secret_key"), 5));

        store.addDatabase(db1);
        store.addDatabase(db2);
        store.rebuildColumnIndex();

        // 1. Column Gathering test: "username" appears in 3 tables across 2 databases
        List<ColumnOccurrence> userOccurrences = store.getColumnOccurrences("username");
        assertEquals(3, userOccurrences.size());

        // 2. Keyword Search test: partial match "pass"
        List<ColumnOccurrence> passResults = store.searchColumns("pass", false);
        assertEquals(1, passResults.size());
        assertEquals("password_hash", passResults.get(0).getColumnName());

        // 3. Keyword Search test: partial match "secret"
        List<ColumnOccurrence> secretResults = store.searchColumns("secret", false);
        assertEquals(1, secretResults.size());
        assertEquals("secret_key", secretResults.get(0).getColumnName());

        // 4. Keyword Search test: regex match "(pass|token|secret)"
        List<ColumnOccurrence> regexResults = store.searchColumns("(pass|token|secret)", true);
        assertEquals(3, regexResults.size());
    }

    @Test
    public void testSessionSaveAndLoad(@TempDir Path tempDir) {
        SqlmapDataStore store = new SqlmapDataStore();
        store.setSqlmapRootPath(tempDir.toString());

        DatabaseModel db = new DatabaseModel("crm_db", "crm.local");
        db.addTable(new TableMetadata("crm.local", "crm_db", "customers", null, List.of("id", "email", "token"), 50));
        store.addDatabase(db);
        store.rebuildColumnIndex();
        store.addBookmark("crm_db.customers");
        store.setNote("crm_db.customers", "Contains customer auth tokens");

        SQLMapPersistenceManager manager = new SQLMapPersistenceManager(null);
        manager.bindContext(null, store);

        File sessionFile = tempDir.resolve("test_session.json").toFile();
        boolean saved = manager.performSave(sessionFile);
        assertTrue(saved);
        assertTrue(sessionFile.exists());

        // Now create a fresh store and load
        SqlmapDataStore reloadedStore = new SqlmapDataStore();
        SQLMapPersistenceManager reloadManager = new SQLMapPersistenceManager(null);
        reloadManager.bindContext(null, reloadedStore);

        boolean loaded = reloadManager.loadSession(sessionFile, false);
        assertTrue(loaded);
        assertEquals(1, reloadedStore.getAllDatabases().size());
        assertEquals(1, reloadedStore.getAllTables().size());
        assertTrue(reloadedStore.isBookmarked("crm_db.customers"));
        assertEquals("Contains customer auth tokens", reloadedStore.getNote("crm_db.customers"));
    }
}
