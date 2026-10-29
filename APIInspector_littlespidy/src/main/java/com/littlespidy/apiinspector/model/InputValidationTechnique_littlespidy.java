// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Representation of an input validation fuzzing technique / category.
 */
public class InputValidationTechnique_littlespidy {

    private final String id;
    private final String category;
    private final String description;
    private final List<String> samplePayloads;
    private final List<String> errorSignatures;
    private boolean enabled;

    public InputValidationTechnique_littlespidy(
            String id, String category, String description,
            List<String> samplePayloads, List<String> errorSignatures, boolean enabled) {
        this.id = id;
        this.category = category;
        this.description = description;
        this.samplePayloads = samplePayloads != null ? samplePayloads : new ArrayList<>();
        this.errorSignatures = errorSignatures != null ? errorSignatures : new ArrayList<>();
        this.enabled = enabled;
    }

    public InputValidationTechnique_littlespidy(
            String id, String category, String description,
            List<String> samplePayloads, List<String> errorSignatures) {
        this(id, category, description, samplePayloads, errorSignatures, true);
    }

    public String getId() {
        return id;
    }

    public String getCategory() {
        return category;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getSamplePayloads() {
        return samplePayloads;
    }

    public List<String> getErrorSignatures() {
        return errorSignatures;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getPayloadCount() {
        return samplePayloads.size();
    }

    public boolean isBlns() {
        return id != null && id.startsWith("blns_");
    }

    /**
     * Default list of input validation vulnerability categories and payloads,
     * including core OWASP attacks and the Big List of Naughty Strings (BLNS).
     */
    public static List<InputValidationTechnique_littlespidy> getDefaultTechniques() {
        List<InputValidationTechnique_littlespidy> list = new ArrayList<>();

        list.add(new InputValidationTechnique_littlespidy(
                "sqli", "SQL Injection (SQLi)",
                "Tests for SQL syntax errors, boolean differences, and database disclosure",
                Arrays.asList(
                        "' OR '1'='1' -- -",
                        "' UNION SELECT null, null -- -",
                        "1' AND 1=CONVERT(int, @@version) --",
                        "\" OR \"1\"=\"1",
                        "'; WAITFOR DELAY '0:0:5'--"
                ),
                Arrays.asList(
                        "syntax error", "sql error", "mysql_", "pg_query", "ora-",
                        "unclosed quotation", "unterminated string", "SQLSTATE", "sqlite3",
                        "microsoft ole db", "odbc drivers"
                )
        ));

        list.add(new InputValidationTechnique_littlespidy(
                "xss", "Cross-Site Scripting (XSS)",
                "Checks for unencoded reflection in response content",
                Arrays.asList(
                        "<script>alert(1)</script>",
                        "\"><img src=x onerror=alert(1)>",
                        "javascript:alert(1)",
                        "<svg/onload=alert(1)>",
                        "'\"><svg/onload=alert(1)>"
                ),
                Arrays.asList("<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>")
        ));

        list.add(new InputValidationTechnique_littlespidy(
                "path_traversal", "Path Traversal / LFI",
                "Tests directory traversal and sensitive system file retrieval",
                Arrays.asList(
                        "../../../../etc/passwd",
                        "..\\..\\..\\..\\windows\\win.ini",
                        "....//....//....//etc/passwd",
                        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                        "/etc/passwd%00.png"
                ),
                Arrays.asList("root:x:0:0", "[extensions]", "[fonts]", "for 16-bit app support")
        ));

        list.add(new InputValidationTechnique_littlespidy(
                "command_injection", "OS Command Injection",
                "Tests shell command concatenation and execution output",
                Arrays.asList(
                        "; id",
                        "| id",
                        "`id`",
                        "$(id)",
                        "& whoami"
                ),
                Arrays.asList("uid=", "gid=", "root", "groups=")
        ));

        list.add(new InputValidationTechnique_littlespidy(
                "ssti", "Server-Side Template (SSTI)",
                "Tests template expression execution in Jinja2, Twig, Freemarker, etc.",
                Arrays.asList(
                        "{{7*7}}",
                        "${7*7}",
                        "<%= 7*7 %>",
                        "#{7*7}",
                        "*{7*7}"
                ),
                Arrays.asList("49", "freemarker", "org.apache.velocity")
        ));

        list.add(new InputValidationTechnique_littlespidy(
                "boundary_overflow", "Boundary & Overflow",
                "Tests extreme numbers, null bytes, long strings, and type confusion",
                Arrays.asList(
                        "99999999999999999999",
                        "-1",
                        "0",
                        "%00",
                        "A".repeat(500),
                        "'\\\"><;|\\\\][}{`$"
                ),
                Arrays.asList(
                        "IndexOutOfBoundsException", "NumberFormatException", "NullPointerException",
                        "ClassCastException", "TypeError", "ValueError", "stack trace", "traceback"
                )
        ));

        // Add Big List of Naughty Strings (BLNS) categories
        try {
            list.addAll(NaughtyStringsParser_littlespidy.loadDefaultBlnsTechniques());
        } catch (Exception ignored) {
        }

        return list;
    }
}
