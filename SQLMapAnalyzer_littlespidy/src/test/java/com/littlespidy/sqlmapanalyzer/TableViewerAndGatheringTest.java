// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.model.DatabaseModel;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;
import com.littlespidy.sqlmapanalyzer.ui.analysis.ColumnGatheringPanel;
import com.littlespidy.sqlmapanalyzer.ui.viewer.TableViewerPanel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class TableViewerAndGatheringTest {

    private SqlmapDataStore dataStore;

    @BeforeEach
    public void setUp() {
        dataStore = new SqlmapDataStore();

        DatabaseModel db1 = new DatabaseModel("ecommerce_db", "10.0.0.5_8080");
        TableMetadata t1 = new TableMetadata("10.0.0.5_8080", "ecommerce_db", "users",
                new File("dummy.csv"), List.of("id", "username", "password_hash", "ssn", "account_num"), 10);
        db1.addTable(t1);

        DatabaseModel db2 = new DatabaseModel("auth_service_db", "10.0.0.6_8443");
        TableMetadata t2 = new TableMetadata("10.0.0.6_8443", "auth_service_db", "accounts",
                new File("dummy2.csv"), List.of("account_id", "security_token", "social_security_num"), 5);
        db2.addTable(t2);

        dataStore.addDatabase(db1);
        dataStore.addDatabase(db2);
        dataStore.rebuildColumnIndex();
    }

    @Test
    public void testTableViewerShowsOnlyDatabaseName() throws Exception {
        TableViewerPanel panel = new TableViewerPanel(dataStore);
        panel.refreshDatabases();

        assertEquals("ecommerce_db", panel.getSelectedDatabaseName());

        Field dbComboField = TableViewerPanel.class.getDeclaredField("dbComboBox");
        dbComboField.setAccessible(true);
        @SuppressWarnings("unchecked")
        JComboBox<String> dbComboBox = (JComboBox<String>) dbComboField.get(panel);

        assertEquals(2, dbComboBox.getItemCount());
        assertEquals("ecommerce_db", dbComboBox.getItemAt(0));
        assertEquals("auth_service_db", dbComboBox.getItemAt(1));

        panel.selectDatabaseAndTable("auth_service_db", "accounts");
        assertEquals("auth_service_db", panel.getSelectedDatabaseName());
        assertEquals("accounts", panel.getSelectedTableName());
    }

    @Test
    public void testColumnGatheringPresets() throws Exception {
        ColumnGatheringPanel panel = new ColumnGatheringPanel(dataStore, null);
        panel.refreshData();

        Field tableField = ColumnGatheringPanel.class.getDeclaredField("columnsTable");
        tableField.setAccessible(true);
        JTable columnsTable = (JTable) tableField.get(panel);

        assertTrue(columnsTable.getRowCount() >= 2);

        Method applyPresetMethod = ColumnGatheringPanel.class.getDeclaredMethod("applyPreset", String.class);
        applyPresetMethod.setAccessible(true);

        applyPresetMethod.invoke(panel, "SSN");
        assertTrue(columnsTable.getRowCount() >= 1);

        applyPresetMethod.invoke(panel, "Account");
        assertTrue(columnsTable.getRowCount() >= 1);

        applyPresetMethod.invoke(panel, "Security");
        assertTrue(columnsTable.getRowCount() >= 1);

        applyPresetMethod.invoke(panel, "Social");
        assertTrue(columnsTable.getRowCount() >= 1);

        applyPresetMethod.invoke(panel, "");
        assertTrue(columnsTable.getRowCount() >= 5);
    }
}
