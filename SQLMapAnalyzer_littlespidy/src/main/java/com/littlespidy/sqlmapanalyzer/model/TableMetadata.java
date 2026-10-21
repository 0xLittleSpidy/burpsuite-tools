// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.model;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Metadata representing a dumped database table in SQLMap output.
 * Plain ASCII text only.
 */
public class TableMetadata implements Serializable {
    private static final long serialVersionUID = 1L;

    private String targetHost;
    private String databaseName;
    private String tableName;
    private String csvFilePath;
    private List<String> columnNames;
    private int rowCount;
    private long fileSizeBytes;

    public TableMetadata() {
        this.columnNames = new ArrayList<>();
    }

    public TableMetadata(String targetHost, String databaseName, String tableName, File csvFile, List<String> columnNames, int rowCount) {
        this.targetHost = targetHost != null ? targetHost : "";
        this.databaseName = databaseName != null ? databaseName : "";
        this.tableName = tableName != null ? tableName : "";
        this.csvFilePath = csvFile != null ? csvFile.getAbsolutePath() : "";
        this.columnNames = columnNames != null ? new ArrayList<>(columnNames) : new ArrayList<>();
        this.rowCount = rowCount;
        this.fileSizeBytes = (csvFile != null && csvFile.exists()) ? csvFile.length() : 0L;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(String targetHost) {
        this.targetHost = targetHost;
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

    public String getCsvFilePath() {
        return csvFilePath;
    }

    public void setCsvFilePath(String csvFilePath) {
        this.csvFilePath = csvFilePath;
    }

    public File getCsvFile() {
        return (csvFilePath != null && !csvFilePath.isBlank()) ? new File(csvFilePath) : null;
    }

    public List<String> getColumnNames() {
        return Collections.unmodifiableList(columnNames);
    }

    public void setColumnNames(List<String> columnNames) {
        this.columnNames = columnNames != null ? new ArrayList<>(columnNames) : new ArrayList<>();
    }

    public int getColumnCount() {
        return columnNames != null ? columnNames.size() : 0;
    }

    public int getRowCount() {
        return rowCount;
    }

    public void setRowCount(int rowCount) {
        this.rowCount = rowCount;
    }

    public long getFileSizeBytes() {
        return fileSizeBytes;
    }

    public void setFileSizeBytes(long fileSizeBytes) {
        this.fileSizeBytes = fileSizeBytes;
    }

    public String getQualifiedName() {
        if (targetHost != null && !targetHost.isBlank()) {
            return targetHost + " / " + databaseName + "." + tableName;
        }
        return databaseName + "." + tableName;
    }

    @Override
    public String toString() {
        return tableName + " (" + rowCount + " rows, " + getColumnCount() + " cols)";
    }
}
