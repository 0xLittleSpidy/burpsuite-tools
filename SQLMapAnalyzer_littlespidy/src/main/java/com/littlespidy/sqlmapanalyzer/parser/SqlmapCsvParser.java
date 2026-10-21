// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.parser;

import com.littlespidy.sqlmapanalyzer.model.TableData;
import com.littlespidy.sqlmapanalyzer.model.TableMetadata;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Robust RFC-4180 compliant CSV parser for SQLMap output files.
 * Plain ASCII text only.
 */
public class SqlmapCsvParser {

    /**
     * Efficiently parses only table headers and total row count without keeping data rows in memory.
     */
    public TableMetadata parseMetadata(String targetHost, String dbName, String tableName, File csvFile) throws IOException {
        if (csvFile == null || !csvFile.exists()) {
            throw new FileNotFoundException("CSV file not found: " + (csvFile != null ? csvFile.getAbsolutePath() : "null"));
        }

        List<String> headers = new ArrayList<>();
        int rowCount = 0;

        try (Reader reader = new InputStreamReader(new FileInputStream(csvFile), StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.builder()
                     .setHeader()
                     .setSkipHeaderRecord(false)
                     .setIgnoreEmptyLines(true)
                     .setTrim(false)
                     .build()
                     .parse(reader)) {

            List<String> headerNames = parser.getHeaderNames();
            if (headerNames != null) {
                headers.addAll(headerNames);
            }

            for (CSVRecord record : parser) {
                // If headerNames was empty (e.g. no explicit header row detected), use first row
                if (headers.isEmpty() && parser.getCurrentLineNumber() == 1) {
                    for (int i = 0; i < record.size(); i++) {
                        headers.add(record.get(i).trim());
                    }
                } else {
                    rowCount++;
                }
            }
        }

        return new TableMetadata(targetHost, dbName, tableName, csvFile, headers, rowCount);
    }

    /**
     * Parses the full table contents into memory for viewing.
     */
    public TableData parseFullTable(File csvFile) throws IOException {
        if (csvFile == null || !csvFile.exists()) {
            throw new FileNotFoundException("CSV file not found: " + (csvFile != null ? csvFile.getAbsolutePath() : "null"));
        }

        List<String> headers = new ArrayList<>();
        List<List<String>> rows = new ArrayList<>();

        try (Reader reader = new InputStreamReader(new FileInputStream(csvFile), StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.builder()
                     .setHeader()
                     .setSkipHeaderRecord(true)
                     .setIgnoreEmptyLines(true)
                     .setTrim(false)
                     .build()
                     .parse(reader)) {

            List<String> headerNames = parser.getHeaderNames();
            if (headerNames != null) {
                headers.addAll(headerNames);
            }

            for (CSVRecord record : parser) {
                List<String> rowValues = new ArrayList<>(record.size());
                for (int i = 0; i < record.size(); i++) {
                    String val = record.get(i);
                    rowValues.add(val != null ? val : "");
                }
                rows.add(rowValues);
            }
        }

        return new TableData(headers, rows);
    }

    /**
     * Exports rows to a CSV file.
     */
    public void exportToCsv(File outputFile, List<String> headers, List<List<String>> rows) throws IOException {
        if (outputFile == null) return;
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8);
             CSVPrinter printer = new CSVPrinter(writer, CSVFormat.DEFAULT)) {

            if (headers != null && !headers.isEmpty()) {
                printer.printRecord(headers);
            }
            if (rows != null) {
                for (List<String> row : rows) {
                    printer.printRecord(row);
                }
            }
            printer.flush();
        }
    }
}
