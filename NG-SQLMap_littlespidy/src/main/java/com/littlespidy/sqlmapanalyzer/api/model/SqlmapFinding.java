// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api.model;

import java.io.Serializable;

/**
 * Model representing a vulnerability finding or extracted artifact from a SQLMap scan.
 * Plain ASCII text only.
 */
public class SqlmapFinding implements Serializable {
    private static final long serialVersionUID = 1L;

    private int type;
    private String parameter = "";
    private String dbms = "";
    private String injectionType = "";
    private String payload = "";
    private String details = "";

    public SqlmapFinding() {}

    public SqlmapFinding(int type, String parameter, String dbms, String injectionType, String payload, String details) {
        this.type = type;
        this.parameter = parameter != null ? parameter : "";
        this.dbms = dbms != null ? dbms : "";
        this.injectionType = injectionType != null ? injectionType : "";
        this.payload = payload != null ? payload : "";
        this.details = details != null ? details : "";
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getParameter() {
        return parameter;
    }

    public void setParameter(String parameter) {
        this.parameter = parameter != null ? parameter : "";
    }

    public String getDbms() {
        return dbms;
    }

    public void setDbms(String dbms) {
        this.dbms = dbms != null ? dbms : "";
    }

    public String getInjectionType() {
        return injectionType;
    }

    public void setInjectionType(String injectionType) {
        this.injectionType = injectionType != null ? injectionType : "";
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload != null ? payload : "";
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details != null ? details : "";
    }
}
