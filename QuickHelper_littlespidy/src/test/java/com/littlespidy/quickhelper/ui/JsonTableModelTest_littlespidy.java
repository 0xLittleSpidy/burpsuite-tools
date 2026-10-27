// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class JsonTableModelTest_littlespidy {

    private JsonTableModel_littlespidy model;

    @BeforeEach
    void setUp() {
        model = new JsonTableModel_littlespidy();
    }

    @Test
    void testInitialState() {
        assertEquals(0, model.getRowCount());
        assertEquals(0, model.getColumnCount());
        assertFalse(model.isCellEditable(0, 0));
        assertNull(model.getValueAt(0, 0));
    }

    @Test
    void testSetTableDataAndRetrieval() {
        List<String> cols = List.of("ID", "Username", "Status");
        List<List<String>> rows = List.of(
                List.of("1", "alice", "active"),
                List.of("2", "bob", "disabled")
        );

        model.setTableData(cols, rows);

        assertEquals(3, model.getColumnCount());
        assertEquals(2, model.getRowCount());
        assertEquals("ID", model.getColumnName(0));
        assertEquals("Username", model.getColumnName(1));
        assertEquals("Status", model.getColumnName(2));

        assertEquals("1", model.getValueAt(0, 0));
        assertEquals("alice", model.getValueAt(0, 1));
        assertEquals("active", model.getValueAt(0, 2));

        assertEquals("2", model.getValueAt(1, 0));
        assertEquals("bob", model.getValueAt(1, 1));
        assertEquals("disabled", model.getValueAt(1, 2));

        assertEquals(List.of("1", "alice", "active"), model.getRowValues(0));

        model.clear();
        assertEquals(0, model.getRowCount());
        assertEquals(0, model.getColumnCount());
    }
}
