// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the Big List of Naughty Strings (BLNS) wordlist and custom fuzzing lists.
 * Categorizes payloads into structured input validation attack techniques.
 */
public class NaughtyStringsParser_littlespidy {

    private static final String DEFAULT_RESOURCE_PATH = "/com/littlespidy/apiinspector/wordlists/big-list-of-naughty-strings.txt";

    public static List<InputValidationTechnique_littlespidy> loadDefaultBlnsTechniques() {
        InputStream is = NaughtyStringsParser_littlespidy.class.getResourceAsStream(DEFAULT_RESOURCE_PATH);
        if (is == null) {
            // Fallback: check file directly relative to working directory or repo root
            File f = new File("src/main/resources/com/littlespidy/apiinspector/wordlists/big-list-of-naughty-strings.txt");
            if (!f.exists()) {
                f = new File("APIInspector_littlespidy/src/main/resources/com/littlespidy/apiinspector/wordlists/big-list-of-naughty-strings.txt");
            }
            if (f.exists()) {
                try {
                    is = new FileInputStream(f);
                } catch (Exception ignored) {
                }
            }
        }

        if (is != null) {
            try {
                return parseBlnsStream(is);
            } catch (Exception ignored) {
            }
        }

        return createFallbackBlnsTechniques();
    }

    public static List<InputValidationTechnique_littlespidy> parseBlnsStream(InputStream is) {
        Map<String, List<String>> sectionMap = new LinkedHashMap<>();
        String currentSection = "Reserved Strings";

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (line.startsWith("#\t") || (line.startsWith("#") && !line.startsWith("# ") && trimmed.length() > 2)) {
                    String rawHeader = trimmed.replaceFirst("^#+", "").trim();
                    if (!rawHeader.isEmpty() && !rawHeader.toLowerCase().startsWith("strings which")
                            && !rawHeader.toLowerCase().startsWith("characters which")
                            && !rawHeader.toLowerCase().startsWith("credit:")) {
                        currentSection = rawHeader;
                    }
                } else if (!trimmed.isEmpty() && !line.startsWith("#")) {
                    sectionMap.computeIfAbsent(currentSection, k -> new ArrayList<>()).add(line);
                }
            }
        } catch (Exception ignored) {
        }

        return groupIntoTechniques(sectionMap);
    }

    private static List<InputValidationTechnique_littlespidy> groupIntoTechniques(Map<String, List<String>> rawSections) {
        List<InputValidationTechnique_littlespidy> techniques = new ArrayList<>();

        List<String> reservedStrings = new ArrayList<>();
        List<String> numericStrings = new ArrayList<>();
        List<String> specialChars = new ArrayList<>();
        List<String> unicodeStrings = new ArrayList<>();
        List<String> scriptInjection = new ArrayList<>();
        List<String> sqlAndCode = new ArrayList<>();
        List<String> unwantedInterpolation = new ArrayList<>();
        List<String> fileTraversal = new ArrayList<>();
        List<String> msdosNames = new ArrayList<>();
        List<String> terminalPrompt = new ArrayList<>();

        for (Map.Entry<String, List<String>> entry : rawSections.entrySet()) {
            String sec = entry.getKey().toLowerCase();
            List<String> list = entry.getValue();

            if (sec.contains("msdos") || sec.contains("windows special") || sec.contains("filenames")) {
                msdosNames.addAll(list);
            } else if (sec.contains("reserved")) {
                reservedStrings.addAll(list);
            } else if (sec.contains("numeric") || sec.contains("number")) {
                numericStrings.addAll(list);
            } else if (sec.contains("special") || sec.contains("punctuation") || sec.contains("quotation") || sec.contains("control")) {
                specialChars.addAll(list);
            } else if (sec.contains("unicode") || sec.contains("two-byte") || sec.contains("changing length")
                    || sec.contains("right-to-left") || sec.contains("zalgo") || sec.contains("upsidedown")
                    || sec.contains("japanese") || sec.contains("emoji")) {
                unicodeStrings.addAll(list);
            } else if (sec.contains("script injection")) {
                scriptInjection.addAll(list);
            } else if (sec.contains("sql") || sec.contains("server code") || sec.contains("command injection")) {
                sqlAndCode.addAll(list);
            } else if (sec.contains("interpolation")) {
                unwantedInterpolation.addAll(list);
            } else if (sec.contains("file inclusion") || sec.contains("xxe") || sec.contains("vulnerabilities")) {
                fileTraversal.addAll(list);
            } else {
                terminalPrompt.addAll(list);
            }
        }

        techniques.add(new InputValidationTechnique_littlespidy(
                "blns_reserved", "BLNS: Reserved Identifiers",
                "Tests keywords that may conflict with internal language interpreters (null, undef, None, True)",
                reservedStrings,
                Arrays.asList("NullPointerException", "undefined", "TypeError", "ReferenceError", "NoneType")
        ));

        techniques.add(new InputValidationTechnique_littlespidy(
                "blns_numeric", "BLNS: Numeric Boundaries & Extremes",
                "Tests extreme integers, floating point errors, zero division, and NaN overflows",
                numericStrings,
                Arrays.asList("NumberFormatException", "ArithmeticException", "divided by zero", "Overflow", "NaN")
        ));

        techniques.add(new InputValidationTechnique_littlespidy(
                "blns_special", "BLNS: Special Characters & Quotation Quirks",
                "Tests misplaced quotes, delimiters, and C0/C1 non-whitespace control codes",
                specialChars,
                Arrays.asList("syntax error", "parse error", "unterminated string", "unclosed quotation", "unexpected token")
        ));

        techniques.add(new InputValidationTechnique_littlespidy(
                "blns_unicode", "BLNS: Unicode & Encoding Edge-Cases",
                "Tests two-byte characters, case expansion, right-to-left overrides, and surrogate pairs",
                unicodeStrings,
                Arrays.asList("CharacterCodingException", "MalformedInputException", "UnicodeDecodeError", "utf8", "encoding error")
        ));

        techniques.add(new InputValidationTechnique_littlespidy(
                "blns_interpolation", "BLNS: Format Strings & Unwanted Interpolation",
                "Tests printf format string specifiers and accidental shell evaluation (%s, %x, %n)",
                unwantedInterpolation,
                Collections.emptyList()
        ));

        return techniques;
    }

    /**
     * Loads all individual payloads across the refined input validation wordlists.
     * Each payload is represented as an individual InputValidationPayloadItem_littlespidy row.
     */
    public static List<InputValidationPayloadItem_littlespidy> loadAllIndividualPayloads() {
        List<InputValidationPayloadItem_littlespidy> items = new ArrayList<>();

        // Load Big List of Naughty Strings individual payloads for retained categories
        List<InputValidationTechnique_littlespidy> blnsTechniques = loadDefaultBlnsTechniques();
        for (InputValidationTechnique_littlespidy t : blnsTechniques) {
            List<String> payloads = t.getSamplePayloads();
            for (int i = 0; i < payloads.size(); i++) {
                String id = t.getId() + "_" + String.format("%03d", i + 1);
                items.add(new InputValidationPayloadItem_littlespidy(
                        id,
                        t.getCategory(),
                        payloads.get(i),
                        Collections.emptyList(),
                        t.getDescription(),
                        true,
                        true,
                        false
                ));
            }
        }

        return items;
    }

    /**
     * Parses a custom wordlist file into individual payload items.
     */
    public static List<InputValidationPayloadItem_littlespidy> parseCustomFileToPayloads(File file) throws Exception {
        if (file == null || !file.exists()) {
            throw new IllegalArgumentException("File does not exist");
        }

        List<InputValidationPayloadItem_littlespidy> items = new ArrayList<>();
        String name = file.getName();
        String prefix = "custom_" + name.toLowerCase().replaceAll("[^a-z0-9_]", "_");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            int counter = 1;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    String id = prefix + "_" + String.format("%03d", counter++);
                    items.add(new InputValidationPayloadItem_littlespidy(
                            id,
                            "Custom: " + name,
                            trimmed,
                            Collections.emptyList(),
                            "Custom wordlist payload from " + name,
                            true,
                            false,
                            true
                    ));
                }
            }
        }

        return items;
    }

    public static InputValidationTechnique_littlespidy parseCustomFile(File file) throws Exception {
        if (file == null || !file.exists()) {
            throw new IllegalArgumentException("File does not exist");
        }

        List<String> payloads = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    payloads.add(trimmed);
                }
            }
        }

        String name = file.getName();
        String id = "custom_" + name.toLowerCase().replaceAll("[^a-z0-9_]", "_");
        return new InputValidationTechnique_littlespidy(
                id,
                "Custom Wordlist: " + name + " (" + payloads.size() + " payloads)",
                "Custom wordlist loaded from " + file.getAbsolutePath(),
                payloads,
                Arrays.asList("error", "exception", "failed", "syntax", "warning")
        );
    }

    private static List<InputValidationTechnique_littlespidy> createFallbackBlnsTechniques() {
        return Arrays.asList(
                new InputValidationTechnique_littlespidy(
                        "blns_reserved", "BLNS: Reserved Identifiers",
                        "Reserved language keywords",
                        Arrays.asList("undefined", "undef", "null", "NULL", "nil", "None", "true", "false", "True", "False"),
                        Arrays.asList("NullPointerException", "undefined", "TypeError")
                ),
                new InputValidationTechnique_littlespidy(
                        "blns_numeric", "BLNS: Numeric Boundaries & Extremes",
                        "Numeric extreme strings",
                        Arrays.asList("0", "1", "-1", "1/0", "0/0", "NaN", "Infinity", "-Infinity", "0xffffffff", "99999999999999999999"),
                        Arrays.asList("NumberFormatException", "ArithmeticException")
                )
        );
    }
}
