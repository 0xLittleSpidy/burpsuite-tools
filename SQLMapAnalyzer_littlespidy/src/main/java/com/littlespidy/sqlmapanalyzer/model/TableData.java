// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * In-memory representation of table columns and row records.
 * Plain ASCII text only.
 */
public class TableData implements Serializable {
    private static final long serialVersionUID = 1L;

    private List<String> headers;
    private List<List<String>> rows;

    public TableData() {
        this.headers = new ArrayList<>();
        this.rows = new ArrayList<>();
    }

    public TableData(List<String> headers, List<List<String>> rows) {
        this.headers = headers != null ? new ArrayList<>(headers) : new ArrayList<>();
        this.rows = rows != null ? new ArrayList<>(rows) : new ArrayList<>();
    }

    public List<String> getHeaders() {
        return Collections.unmodifiableList(headers);
    }

    public void setHeaders(List<String> headers) {
        this.headers = headers != null ? new ArrayList<>(headers) : new ArrayList<>();
    }

    public List<List<String>> getRows() {
        return Collections.unmodifiableList(rows);
    }

    public void setRows(List<List<String>> rows) {
        this.rows = rows != null ? new ArrayList<>(rows) : new ArrayList<>();
    }

    public int getColumnCount() {
        return headers != null ? headers.size() : 0;
    }

    public int getRowCount() {
        return rows != null ? rows.size() : 0;
    }
}
