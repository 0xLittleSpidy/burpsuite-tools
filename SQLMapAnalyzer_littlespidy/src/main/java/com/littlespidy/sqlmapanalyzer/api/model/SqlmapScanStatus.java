// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api.model;

import java.io.Serializable;

/**
 * Scan status response from the SQLMap REST API.
 * Plain ASCII text only.
 */
public class SqlmapScanStatus implements Serializable {
    private static final long serialVersionUID = 1L;

    private boolean success;
    private String status = "not running";
    private int returncode = -1;

    public SqlmapScanStatus() {}

    public SqlmapScanStatus(boolean success, String status, int returncode) {
        this.success = success;
        this.status = status != null ? status : "not running";
        this.returncode = returncode;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getStatus() {
        return status != null ? status : "not running";
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getReturncode() {
        return returncode;
    }

    public void setReturncode(int returncode) {
        this.returncode = returncode;
    }

    public boolean isRunning() {
        return "running".equalsIgnoreCase(status);
    }

    public boolean isTerminated() {
        return "terminated".equalsIgnoreCase(status);
    }
}
