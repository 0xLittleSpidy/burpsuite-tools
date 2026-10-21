// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.model;

import java.io.Serializable;

/**
 * Tracks an occurrence of a column name across a database and table.
 * Plain ASCII text only.
 */
public class ColumnOccurrence implements Serializable {
    private static final long serialVersionUID = 1L;

    private String columnName;
    private String databaseName;
    private String tableName;
    private String targetHost;
    private int rowCount;
    private String csvFilePath;

    public ColumnOccurrence() {}

    public ColumnOccurrence(String columnName, String databaseName, String tableName, String targetHost, int rowCount, String csvFilePath) {
        this.columnName = columnName;
        this.databaseName = databaseName;
        this.tableName = tableName;
        this.targetHost = targetHost != null ? targetHost : "";
        this.rowCount = rowCount;
        this.csvFilePath = csvFilePath != null ? csvFilePath : "";
    }

    public String getColumnName() {
        return columnName;
    }

    public void setColumnName(String columnName) {
        this.columnName = columnName;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(String targetHost) {
        this.targetHost = targetHost;
    }

    public int getRowCount() {
        return rowCount;
    }

    public void setRowCount(int rowCount) {
        this.rowCount = rowCount;
    }

    public String getCsvFilePath() {
        return csvFilePath;
    }

    public void setCsvFilePath(String csvFilePath) {
        this.csvFilePath = csvFilePath;
    }
}
