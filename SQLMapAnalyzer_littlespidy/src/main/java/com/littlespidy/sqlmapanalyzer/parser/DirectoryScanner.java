// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.parser;

import com.littlespidy.sqlmapanalyzer.model.DatabaseModel;
import com.littlespidy.sqlmapanalyzer.model.SqlmapDataStore;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Scans directories for SQLMap CSV dumps and populates the data store.
 * Supports direct folders, SQLMap target host dumps, and recursive directory structures.
 * Plain ASCII text only.
 */
public class DirectoryScanner {

    public interface ScanProgressListener {
        void onProgress(String currentItem, int tableCount);
        void onComplete(int totalDatabases, int totalTables);
        void onError(String message, Throwable error);
    }

    private final SqlmapCsvParser csvParser;

    public DirectoryScanner() {
        this.csvParser = new SqlmapCsvParser();
    }

    public DirectoryScanner(SqlmapCsvParser csvParser) {
        this.csvParser = csvParser != null ? csvParser : new SqlmapCsvParser();
    }

    /**
     * Scans the root folder and populates the given dataStore.
     */
    public void scanDirectory(File rootDir, SqlmapDataStore dataStore, ScanProgressListener listener) {
        if (rootDir == null || !rootDir.exists() || !rootDir.isDirectory()) {
            if (listener != null) {
                listener.onError("Selected path is not a valid directory: " + (rootDir != null ? rootDir.getAbsolutePath() : "null"), null);
            }
            return;
        }

        dataStore.clear();
        dataStore.setSqlmapRootPath(rootDir.getAbsolutePath());

        List<File> csvFiles = new ArrayList<>();
        collectCsvFiles(rootDir, csvFiles);

        if (csvFiles.isEmpty()) {
            if (listener != null) {
                listener.onError("No CSV files found in " + rootDir.getAbsolutePath(), null);
            }
            return;
        }

        Map<String, DatabaseModel> dbMap = new LinkedHashMap<>();
        int parsedTables = 0;

        for (File csvFile : csvFiles) {
            String fileName = csvFile.getName();
            String tableName = fileName.substring(0, fileName.lastIndexOf('.'));

            File parent = csvFile.getParentFile();
            String dbName = "default";
            String targetHost = "";

            if (parent != null) {
                File grandParent = parent.getParentFile();
                if (grandParent != null && grandParent.getName().equalsIgnoreCase("dump")) {
                    // Structure: <targetHost>/dump/<dbName>/<tableName>.csv
                    dbName = parent.getName();
                    File targetDir = grandParent.getParentFile();
                    if (targetDir != null && !targetDir.equals(rootDir)) {
                        targetHost = targetDir.getName();
                    }
                } else if (parent.getName().equalsIgnoreCase("dump")) {
                    // Structure: <targetHost>/dump/<tableName>.csv
                    dbName = "default";
                    if (grandParent != null && !grandParent.equals(rootDir)) {
                        targetHost = grandParent.getName();
                    }
                } else {
                    // Structure: <rootDir>/<dbName>/<tableName>.csv OR <targetHost>/<dbName>/<tableName>.csv
                    dbName = parent.getName();
                    if (grandParent != null && !grandParent.equals(rootDir)) {
                        targetHost = grandParent.getName();
                    }
                }
            }

            String dbKey = (targetHost != null && !targetHost.isBlank())
                    ? targetHost + "/" + dbName.toLowerCase()
                    : dbName.toLowerCase();

            final String finalDbName = dbName;
            final String finalTargetHost = targetHost;
            DatabaseModel db = dbMap.computeIfAbsent(dbKey, k -> new DatabaseModel(finalDbName, finalTargetHost));

            try {
                TableMetadata meta = csvParser.parseMetadata(targetHost, dbName, tableName, csvFile);
                db.addTable(meta);
                parsedTables++;
                if (listener != null) {
                    listener.onProgress(dbName + "." + tableName, parsedTables);
                }
            } catch (Exception e) {
                // Non-fatal: Record a stub with 0 rows or report error
                TableMetadata stub = new TableMetadata(targetHost, dbName, tableName, csvFile, Collections.emptyList(), 0);
                db.addTable(stub);
            }
        }

        for (DatabaseModel db : dbMap.values()) {
            dataStore.addDatabase(db);
        }

        dataStore.rebuildColumnIndex();

        if (listener != null) {
            listener.onComplete(dataStore.getAllDatabases().size(), parsedTables);
        }
    }

    private void collectCsvFiles(File dir, List<File> result) {
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File f : files) {
            if (f.isDirectory()) {
                collectCsvFiles(f, result);
            } else if (f.isFile() && f.getName().toLowerCase().endsWith(".csv")) {
                result.add(f);
            }
        }
    }
}
