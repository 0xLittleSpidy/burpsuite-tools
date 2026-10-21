// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api.model;

import java.io.Serializable;

/**
 * Log entry returned by the SQLMap REST API.
 * Plain ASCII text only.
 */
public class SqlmapLogEntry implements Serializable {
    private static final long serialVersionUID = 1L;

    private String level;
    private String time;
    private String message;

    public SqlmapLogEntry() {}

    public SqlmapLogEntry(String level, String time, String message) {
        this.level = level != null ? level : "INFO";
        this.time = time != null ? time : "";
        this.message = message != null ? message : "";
    }

    public String getLevel() {
        return level != null ? level : "INFO";
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getTime() {
        return time != null ? time : "";
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getMessage() {
        return message != null ? message : "";
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getFormatted() {
        return "[" + getLevel().toUpperCase() + "] " + getTime() + " - " + getMessage();
    }

    @Override
    public String toString() {
        return getFormatted();
    }
}
