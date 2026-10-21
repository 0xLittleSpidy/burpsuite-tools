// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.persistence;

import com.littlespidy.sqlmapanalyzer.model.DatabaseModel;

import java.io.Serializable;
import java.util.*;

/**
 * Serializable session container for SQLMap Analyzer state.
 * Plain ASCII text only.
 */
public class SQLMapSessionData implements Serializable {
    private static final long serialVersionUID = 1L;

    private String sqlmapRootDirectory = "";
    private long timestamp = System.currentTimeMillis();
    private List<DatabaseModel> databases = new ArrayList<>();
    private List<String> bookmarks = new ArrayList<>();
    private Map<String, String> notes = new HashMap<>();
    private String selectedDatabase = "";
    private String selectedTable = "";

    public SQLMapSessionData() {}

    public String getSqlmapRootDirectory() {
        return sqlmapRootDirectory;
    }

    public void setSqlmapRootDirectory(String sqlmapRootDirectory) {
        this.sqlmapRootDirectory = sqlmapRootDirectory;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public List<DatabaseModel> getDatabases() {
        return databases;
    }

    public void setDatabases(List<DatabaseModel> databases) {
        this.databases = databases != null ? databases : new ArrayList<>();
    }

    public List<String> getBookmarks() {
        return bookmarks;
    }

    public void setBookmarks(List<String> bookmarks) {
        this.bookmarks = bookmarks != null ? bookmarks : new ArrayList<>();
    }

    public Map<String, String> getNotes() {
        return notes;
    }

    public void setNotes(Map<String, String> notes) {
        this.notes = notes != null ? notes : new HashMap<>();
    }

    public String getSelectedDatabase() {
        return selectedDatabase;
    }

    public void setSelectedDatabase(String selectedDatabase) {
        this.selectedDatabase = selectedDatabase;
    }

    public String getSelectedTable() {
        return selectedTable;
    }

    public void setSelectedTable(String selectedTable) {
        this.selectedTable = selectedTable;
    }
}
