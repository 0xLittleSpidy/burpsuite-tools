// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.ui;

import com.littlespidy.cacheheaderinspector.model.CacheEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Table model displaying individual URL entries and their respective cache headers.
 * Synchronized for thread-safe UI updates.
 *
 * @author littlespidy
 */
public class CacheEntryTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "#",
        "Status",
        "Method",
        "URL",
        "Host",
        "Content-Type",
        "Cache-Control",
        "Pragma",
        "Expires",
        "Age",
        "ETag",
        "Vary",
        "X-Cache",
        "CF-Cache-Status"
    };

    private final List<CacheEntry> entries = new ArrayList<>();

    public synchronized void updateData(List<CacheEntry> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }

    public synchronized CacheEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < entries.size()) {
            return entries.get(rowIndex);
        }
        return null;
    }

    public synchronized List<CacheEntry> getAllEntries() {
        return new ArrayList<>(entries);
    }

    @Override
    public synchronized int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case 0, 1 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= entries.size()) {
            return null;
        }

        CacheEntry entry = entries.get(rowIndex);
        return switch (columnIndex) {
            case 0  -> entry.id();
            case 1  -> entry.statusCode();
            case 2  -> entry.method();
            case 3  -> entry.url();
            case 4  -> entry.host();
            case 5  -> entry.contentType();
            case 6  -> entry.cacheControl();
            case 7  -> entry.pragma();
            case 8  -> entry.expires();
            case 9  -> entry.age();
            case 10 -> entry.etag();
            case 11 -> entry.vary();
            case 12 -> entry.xCache();
            case 13 -> entry.cfCacheStatus();
            default -> null;
        };
    }
}
