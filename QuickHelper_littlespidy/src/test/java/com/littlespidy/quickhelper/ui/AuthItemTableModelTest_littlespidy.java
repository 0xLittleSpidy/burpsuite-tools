// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import com.littlespidy.quickhelper.model.AuthItem_littlespidy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthItemTableModelTest_littlespidy {

    private AuthItemTableModel_littlespidy model;

    @BeforeEach
    void setUp() {
        model = new AuthItemTableModel_littlespidy();
    }

    @Test
    void testInitialEmptyState() {
        assertEquals(0, model.getRowCount());
        assertEquals(4, model.getColumnCount());
        assertEquals("Type", model.getColumnName(0));
        assertEquals("Name / Key", model.getColumnName(1));
        assertEquals("Length", model.getColumnName(2));
        assertEquals("Value Preview", model.getColumnName(3));
        assertFalse(model.isCellEditable(0, 0));
        assertNull(model.getItem(0));
    }

    @Test
    void testSetItemsAndRetrieval() {
        AuthItem_littlespidy item1 = new AuthItem_littlespidy("Bearer Token", "Bearer (raw token)", "abc123token");
        AuthItem_littlespidy item2 = new AuthItem_littlespidy("Cookie", "session_id", "xyz789");

        model.setItems(Arrays.asList(item1, item2));

        assertEquals(2, model.getRowCount());

        assertEquals("Bearer Token", model.getValueAt(0, 0));
        assertEquals("Bearer (raw token)", model.getValueAt(0, 1));
        assertEquals("11 chars", model.getValueAt(0, 2));
        assertEquals("abc123token", model.getValueAt(0, 3));

        assertEquals("Cookie", model.getValueAt(1, 0));
        assertEquals("session_id", model.getValueAt(1, 1));
        assertEquals("6 chars", model.getValueAt(1, 2));
        assertEquals("xyz789", model.getValueAt(1, 3));

        assertNotNull(model.getItem(0));
        assertEquals("Bearer (raw token)", model.getItem(0).getName());

        model.clear();
        assertEquals(0, model.getRowCount());
    }
}
