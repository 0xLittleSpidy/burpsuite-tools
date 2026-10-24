// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import com.littlespidy.quickhelper.model.ExtensionItem_littlespidy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionTableModelTest_littlespidy {

    private ExtensionTableModel_littlespidy tableModel;
    private List<ExtensionItem_littlespidy> items;

    @BeforeEach
    void setUp() {
        items = new ArrayList<>();
        items.add(new ExtensionItem_littlespidy("ext1", "Alpha Inspector", "Recon", "alpha-1.0.jar", "https://example.com/alpha.jar", "5 MB", "Alpha description"));
        items.add(new ExtensionItem_littlespidy("ext2", "Beta Fuzzer", "Fuzzing", "beta-1.0.jar", "https://example.com/beta.jar", "10 MB", "Beta description"));
        items.add(new ExtensionItem_littlespidy("ext3", "Gamma Auth", "Auth", "gamma-1.0.jar", "https://example.com/gamma.jar", "2 MB", "Gamma description"));
        tableModel = new ExtensionTableModel_littlespidy(items);
    }

    @Test
    void testInitialDimensions() {
        assertEquals(3, tableModel.getRowCount());
        assertEquals(6, tableModel.getColumnCount());
        assertEquals("Select", tableModel.getColumnName(0));
        assertEquals("Extension Name", tableModel.getColumnName(1));
    }

    @Test
    void testCellValues() {
        assertEquals(Boolean.TRUE, tableModel.getValueAt(0, 0));
        assertEquals("Alpha Inspector", tableModel.getValueAt(0, 1));
        assertEquals("Recon", tableModel.getValueAt(0, 2));
        assertEquals("alpha-1.0.jar", tableModel.getValueAt(0, 3));
        assertEquals("5 MB", tableModel.getValueAt(0, 4));
        assertEquals("Idle", tableModel.getValueAt(0, 5));
    }

    @Test
    void testEditableCell() {
        assertTrue(tableModel.isCellEditable(0, 0));
        assertFalse(tableModel.isCellEditable(0, 1));
        assertFalse(tableModel.isCellEditable(0, 2));

        tableModel.setValueAt(Boolean.FALSE, 0, 0);
        assertEquals(Boolean.FALSE, tableModel.getValueAt(0, 0));
    }

    @Test
    void testSelectAll() {
        tableModel.selectAll(false);
        assertFalse((Boolean) tableModel.getValueAt(0, 0));
        assertFalse((Boolean) tableModel.getValueAt(1, 0));
        assertFalse((Boolean) tableModel.getValueAt(2, 0));

        tableModel.selectAll(true);
        assertTrue((Boolean) tableModel.getValueAt(0, 0));
        assertTrue((Boolean) tableModel.getValueAt(1, 0));
        assertTrue((Boolean) tableModel.getValueAt(2, 0));
    }

    @Test
    void testFilter() {
        tableModel.setFilter("beta");
        assertEquals(1, tableModel.getRowCount());
        assertEquals("Beta Fuzzer", tableModel.getValueAt(0, 1));

        tableModel.setFilter("Recon");
        assertEquals(1, tableModel.getRowCount());
        assertEquals("Alpha Inspector", tableModel.getValueAt(0, 1));

        tableModel.setFilter("");
        assertEquals(3, tableModel.getRowCount());
    }
}
