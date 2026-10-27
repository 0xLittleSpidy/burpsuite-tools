// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.model;

import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Model representing tabular data extracted from a JSON payload.
 */
public class JsonTableData_littlespidy {

    private final String title;
    private final List<String> columnNames;
    private final List<List<String>> rowValues;
    private final List<JsonElement> rawRowElements;
    private final boolean isArray;

    public JsonTableData_littlespidy(String title,
                                     List<String> columnNames,
                                     List<List<String>> rowValues,
                                     List<JsonElement> rawRowElements,
                                     boolean isArray) {
        this.title = title != null ? title : "";
        this.columnNames = columnNames != null ? Collections.unmodifiableList(new ArrayList<>(columnNames)) : Collections.emptyList();
        this.rowValues = rowValues != null ? Collections.unmodifiableList(new ArrayList<>(rowValues)) : Collections.emptyList();
        this.rawRowElements = rawRowElements != null ? Collections.unmodifiableList(new ArrayList<>(rawRowElements)) : Collections.emptyList();
        this.isArray = isArray;
    }

    public static JsonTableData_littlespidy empty(String reason) {
        return new JsonTableData_littlespidy(reason, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), false);
    }

    public String getTitle() {
        return title;
    }

    public List<String> getColumnNames() {
        return columnNames;
    }

    public List<List<String>> getRowValues() {
        return rowValues;
    }

    public List<JsonElement> getRawRowElements() {
        return rawRowElements;
    }

    public boolean isArray() {
        return isArray;
    }

    public int getRowCount() {
        return rowValues.size();
    }

    public int getColumnCount() {
        return columnNames.size();
    }
}
