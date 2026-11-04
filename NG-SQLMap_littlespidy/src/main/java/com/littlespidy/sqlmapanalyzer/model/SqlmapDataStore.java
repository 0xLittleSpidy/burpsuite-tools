// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.model;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Central thread-safe data store for SQLMap output databases, tables, and column indexes.
 * Plain ASCII text only.
 */
public class SqlmapDataStore implements Serializable {
    private static final long serialVersionUID = 1L;

    private String sqlmapRootPath = "";
    private final Map<String, DatabaseModel> databases = new LinkedHashMap<>();
    private final Map<String, TableData> tableDataCache = new ConcurrentHashMap<>();
    private final Map<String, List<ColumnOccurrence>> columnIndex = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private final Set<String> bookmarks = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Map<String, String> notes = new ConcurrentHashMap<>();

    public synchronized void setSqlmapRootPath(String sqlmapRootPath) {
        this.sqlmapRootPath = sqlmapRootPath != null ? sqlmapRootPath : "";
    }

    public synchronized String getSqlmapRootPath() {
        return sqlmapRootPath;
    }

    public synchronized void addDatabase(DatabaseModel db) {
        if (db != null && db.getName() != null) {
            String key = (db.getTargetHost() != null && !db.getTargetHost().isBlank())
                    ? db.getTargetHost() + "/" + db.getName().toLowerCase()
                    : db.getName().toLowerCase();
            databases.put(key, db);
        }
    }

    public synchronized DatabaseModel getDatabase(String key) {
        if (key == null) return null;
        return databases.get(key.toLowerCase());
    }

    public synchronized List<DatabaseModel> getAllDatabases() {
        return new ArrayList<>(databases.values());
    }

    public synchronized List<TableMetadata> getAllTables() {
        List<TableMetadata> all = new ArrayList<>();
        for (DatabaseModel db : databases.values()) {
            all.addAll(db.getTables());
        }
        return all;
    }

    public synchronized void putTableData(String cacheKey, TableData data) {
        if (cacheKey != null && data != null) {
            tableDataCache.put(cacheKey.toLowerCase(), data);
        }
    }

    public TableData getCachedTableData(String cacheKey) {
        if (cacheKey == null) return null;
        return tableDataCache.get(cacheKey.toLowerCase());
    }

    public synchronized void rebuildColumnIndex() {
        columnIndex.clear();
        for (DatabaseModel db : databases.values()) {
            for (TableMetadata table : db.getTables()) {
                for (String col : table.getColumnNames()) {
                    if (col == null || col.isBlank()) continue;
                    List<ColumnOccurrence> list = columnIndex.computeIfAbsent(col.trim(), k -> new ArrayList<>());
                    list.add(new ColumnOccurrence(
                            col.trim(),
                            db.getName(),
                            table.getTableName(),
                            db.getTargetHost(),
                            table.getRowCount(),
                            table.getCsvFilePath()
                    ));
                }
            }
        }
    }

    public synchronized List<String> getUniqueColumnNames() {
        return new ArrayList<>(columnIndex.keySet());
    }

    public synchronized List<ColumnOccurrence> getColumnOccurrences(String columnName) {
        if (columnName == null) return Collections.emptyList();
        List<ColumnOccurrence> list = columnIndex.get(columnName.trim());
        return list != null ? Collections.unmodifiableList(list) : Collections.emptyList();
    }

    public synchronized List<ColumnOccurrence> searchColumns(String keyword, boolean regex) {
        if (keyword == null || keyword.isBlank()) {
            return Collections.emptyList();
        }

        List<ColumnOccurrence> matches = new ArrayList<>();
        if (regex) {
            try {
                Pattern pattern = Pattern.compile(keyword, Pattern.CASE_INSENSITIVE);
                for (Map.Entry<String, List<ColumnOccurrence>> entry : columnIndex.entrySet()) {
                    if (pattern.matcher(entry.getKey()).find()) {
                        matches.addAll(entry.getValue());
                    }
                }
            } catch (Exception e) {
                // If regex is invalid, fall back to literal match
                return searchColumns(keyword, false);
            }
        } else {
            String lower = keyword.toLowerCase();
            for (Map.Entry<String, List<ColumnOccurrence>> entry : columnIndex.entrySet()) {
                if (entry.getKey().toLowerCase().contains(lower)) {
                    matches.addAll(entry.getValue());
                }
            }
        }
        return matches;
    }

    public void addBookmark(String key) {
        if (key != null) bookmarks.add(key.toLowerCase());
    }

    public void removeBookmark(String key) {
        if (key != null) bookmarks.remove(key.toLowerCase());
    }

    public boolean isBookmarked(String key) {
        return key != null && bookmarks.contains(key.toLowerCase());
    }

    public Set<String> getBookmarks() {
        return Collections.unmodifiableSet(bookmarks);
    }

    public void setNote(String key, String note) {
        if (key != null) {
            if (note == null || note.isBlank()) {
                notes.remove(key.toLowerCase());
            } else {
                notes.put(key.toLowerCase(), note);
            }
        }
    }

    public String getNote(String key) {
        if (key == null) return null;
        return notes.get(key.toLowerCase());
    }

    public Map<String, String> getNotes() {
        return Collections.unmodifiableMap(notes);
    }

    public synchronized void clear() {
        sqlmapRootPath = "";
        databases.clear();
        tableDataCache.clear();
        columnIndex.clear();
        bookmarks.clear();
        notes.clear();
    }

    public synchronized boolean isEmpty() {
        return databases.isEmpty();
    }
}
