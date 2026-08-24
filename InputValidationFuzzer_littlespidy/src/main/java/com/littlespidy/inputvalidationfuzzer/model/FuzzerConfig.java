package com.littlespidy.inputvalidationfuzzer.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * User-configurable settings for input validation fuzzing.
 *
 * @author littlespidy
 */
public class FuzzerConfig {
    private int sizeDiffPercent = 300;
    private int maxConcurrentThreads = 10;
    private int delayBetweenRequestsMs = 0;
    private boolean fuzzUrlParams = true;
    private boolean fuzzBodyParams = true;
    private boolean fuzzCookieParams = false;
    private boolean fuzzJsonParams = true;
    private boolean fuzzXmlParams = true;
    private boolean fuzzMultipartParams = true;
    private List<ConfiguredHeader> customHeaders = new ArrayList<>();

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
        "warning:", "notice:", "deprecated:"
    ));

    private List<FuzzPayload> payloads = new ArrayList<>(List.of(
        new FuzzPayload("Empty string", "", "Empty string payload — server may fail to handle missing/empty values."),
        new FuzzPayload("Special characters", "'\\\"><;|\\\\][}{`$", "SQL/Command/XSS special characters — may trigger injection flaws."),
        new FuzzPayload("Long string (200 chars)", "A".repeat(200), "Long string (200 chars) — may trigger buffer or length-handling issues."),
        new FuzzPayload("Negative integer", "-1", "Negative integer (-1) — may cause unexpected behavior in numeric fields."),
        new FuzzPayload("Large integer", "99999999999999999999", "Large integer — may trigger integer overflow or parsing errors."),
        new FuzzPayload("Null byte", "%00", "Null byte (%00) — may cause truncation or bypass validation filters.")
    ));

    public int getSizeDiffPercent() { return sizeDiffPercent; }
    public void setSizeDiffPercent(int sizeDiffPercent) { this.sizeDiffPercent = sizeDiffPercent; }

    public int getMaxConcurrentThreads() { return maxConcurrentThreads; }
    public void setMaxConcurrentThreads(int maxConcurrentThreads) { this.maxConcurrentThreads = maxConcurrentThreads; }

    public int getDelayBetweenRequestsMs() { return delayBetweenRequestsMs; }
    public void setDelayBetweenRequestsMs(int delayBetweenRequestsMs) { this.delayBetweenRequestsMs = delayBetweenRequestsMs; }

    public boolean isFuzzUrlParams() { return fuzzUrlParams; }
    public void setFuzzUrlParams(boolean fuzzUrlParams) { this.fuzzUrlParams = fuzzUrlParams; }

    public boolean isFuzzBodyParams() { return fuzzBodyParams; }
    public void setFuzzBodyParams(boolean fuzzBodyParams) { this.fuzzBodyParams = fuzzBodyParams; }

    public boolean isFuzzCookieParams() { return fuzzCookieParams; }
    public void setFuzzCookieParams(boolean fuzzCookieParams) { this.fuzzCookieParams = fuzzCookieParams; }

    public boolean isFuzzJsonParams() { return fuzzJsonParams; }
    public void setFuzzJsonParams(boolean fuzzJsonParams) { this.fuzzJsonParams = fuzzJsonParams; }

    public boolean isFuzzXmlParams() { return fuzzXmlParams; }
    public void setFuzzXmlParams(boolean fuzzXmlParams) { this.fuzzXmlParams = fuzzXmlParams; }

    public boolean isFuzzMultipartParams() { return fuzzMultipartParams; }
    public void setFuzzMultipartParams(boolean fuzzMultipartParams) { this.fuzzMultipartParams = fuzzMultipartParams; }

    public List<ConfiguredHeader> getCustomHeaders() { return customHeaders; }
    public void setCustomHeaders(List<ConfiguredHeader> customHeaders) { this.customHeaders = customHeaders != null ? new ArrayList<>(customHeaders) : new ArrayList<>(); }

    public List<String> getErrorSignatures() { return errorSignatures; }
    public void setErrorSignatures(List<String> errorSignatures) { this.errorSignatures = errorSignatures; }

    public List<FuzzPayload> getPayloads() { return payloads; }
    public void setPayloads(List<FuzzPayload> payloads) { this.payloads = payloads; }
}
