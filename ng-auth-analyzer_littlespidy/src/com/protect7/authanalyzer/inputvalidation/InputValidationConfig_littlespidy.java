// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.inputvalidation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Configuration options and payload selections for the Input Validation module.
 */
public class InputValidationConfig_littlespidy {

    private boolean fuzzUrlParams = true;
    private boolean fuzzBodyParams = true;
    private boolean fuzzJsonParams = true;
    private boolean fuzzXmlParams = true;
    private boolean fuzzMultipartParams = true;
    private boolean fuzzCookieParams = false;

    private int maxConcurrentThreads = 10;
    private int delayBetweenRequestsMs = 0;
    private int sizeDiffPercent = 300;

    private List<InputValidationPayload_littlespidy> payloads;
    private List<String> errorSignatures = new ArrayList<>(Arrays.asList(
            "syntax error", "sql error", "mysql_", "pg_query", "ora-",
            "unclosed quotation", "unterminated string", "parse error",
            "stack trace", "stacktrace", "traceback", "exception in",
            "fatal error", "internal server error", "segmentation fault",
            "NullPointerException", "IndexOutOfBoundsException",
            "ClassCastException", "NumberFormatException",
            "TypeError", "ValueError", "SyntaxError", "ReferenceError",
            "SQLSTATE", "sqlite3", "microsoft ole db", "odbc drivers",
            "javax.servlet", "at java.", "at org.apache",
            "warning:", "notice:", "deprecated:",
            "root:x:0:0", "[extensions]", "uid=", "gid=", "freemarker"
    ));

    public InputValidationConfig_littlespidy() {
        this.payloads = InputValidationPayloadLoader_littlespidy.loadAllPayloads();
    }

    public boolean isFuzzUrlParams() {
        return fuzzUrlParams;
    }

    public void setFuzzUrlParams(boolean fuzzUrlParams) {
        this.fuzzUrlParams = fuzzUrlParams;
    }

    public boolean isFuzzBodyParams() {
        return fuzzBodyParams;
    }

    public void setFuzzBodyParams(boolean fuzzBodyParams) {
        this.fuzzBodyParams = fuzzBodyParams;
    }

    public boolean isFuzzJsonParams() {
        return fuzzJsonParams;
    }

    public void setFuzzJsonParams(boolean fuzzJsonParams) {
        this.fuzzJsonParams = fuzzJsonParams;
    }

    public boolean isFuzzXmlParams() {
        return fuzzXmlParams;
    }

    public void setFuzzXmlParams(boolean fuzzXmlParams) {
        this.fuzzXmlParams = fuzzXmlParams;
    }

    public boolean isFuzzMultipartParams() {
        return fuzzMultipartParams;
    }

    public void setFuzzMultipartParams(boolean fuzzMultipartParams) {
        this.fuzzMultipartParams = fuzzMultipartParams;
    }

    public boolean isFuzzCookieParams() {
        return fuzzCookieParams;
    }

    public void setFuzzCookieParams(boolean fuzzCookieParams) {
        this.fuzzCookieParams = fuzzCookieParams;
    }

    public int getMaxConcurrentThreads() {
        return maxConcurrentThreads;
    }

    public void setMaxConcurrentThreads(int maxConcurrentThreads) {
        this.maxConcurrentThreads = Math.max(1, maxConcurrentThreads);
    }

    public int getDelayBetweenRequestsMs() {
        return delayBetweenRequestsMs;
    }

    public void setDelayBetweenRequestsMs(int delayBetweenRequestsMs) {
        this.delayBetweenRequestsMs = Math.max(0, delayBetweenRequestsMs);
    }

    public int getSizeDiffPercent() {
        return sizeDiffPercent;
    }

    public void setSizeDiffPercent(int sizeDiffPercent) {
        this.sizeDiffPercent = sizeDiffPercent;
    }

    public List<InputValidationPayload_littlespidy> getPayloads() {
        return payloads;
    }

    public void setPayloads(List<InputValidationPayload_littlespidy> payloads) {
        this.payloads = payloads != null ? payloads : new ArrayList<>();
    }

    public List<String> getErrorSignatures() {
        return errorSignatures;
    }

    public void setErrorSignatures(List<String> errorSignatures) {
        this.errorSignatures = errorSignatures != null ? errorSignatures : new ArrayList<>();
    }

    public void resetToDefaultEssential() {
        if (payloads != null) {
            for (InputValidationPayload_littlespidy p : payloads) {
                p.setEnabled(p.isDefaultEssential());
            }
        }
    }

    public void enableAllPayloads(boolean enable) {
        if (payloads != null) {
            for (InputValidationPayload_littlespidy p : payloads) {
                p.setEnabled(enable);
            }
        }
    }
}
