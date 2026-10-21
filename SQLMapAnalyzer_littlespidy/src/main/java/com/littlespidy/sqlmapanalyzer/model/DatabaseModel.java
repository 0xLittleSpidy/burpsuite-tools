// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.model;

import java.io.Serializable;
import java.util.*;

/**
 * Model representing a database containing tables from SQLMap dumps.
 * Plain ASCII text only.
 */
public class DatabaseModel implements Serializable {
    private static final long serialVersionUID = 1L;

    private String name;
    private String targetHost;
    private final Map<String, TableMetadata> tables = new LinkedHashMap<>();

    public DatabaseModel() {}

    public DatabaseModel(String name, String targetHost) {
        this.name = name;
        this.targetHost = targetHost != null ? targetHost : "";
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(String targetHost) {
        this.targetHost = targetHost;
    }

    public void addTable(TableMetadata table) {
        if (table != null && table.getTableName() != null) {
            tables.put(table.getTableName().toLowerCase(), table);
        }
    }

    public TableMetadata getTable(String tableName) {
        if (tableName == null) return null;
        return tables.get(tableName.toLowerCase());
    }

    public Collection<TableMetadata> getTables() {
        return Collections.unmodifiableCollection(tables.values());
    }

    public List<String> getTableNames() {
        List<String> names = new ArrayList<>();
        for (TableMetadata meta : tables.values()) {
            names.add(meta.getTableName());
        }
        Collections.sort(names);
        return names;
    }

    public int getTableCount() {
        return tables.size();
    }

    public int getTotalRowCount() {
        int total = 0;
        for (TableMetadata meta : tables.values()) {
            total += meta.getRowCount();
        }
        return total;
    }

    public String getDisplayName() {
        if (targetHost != null && !targetHost.isBlank()) {
            return targetHost + " / " + name;
        }
        return name;
    }

    @Override
    public String toString() {
        return getDisplayName() + " (" + getTableCount() + " tables)";
    }
}
