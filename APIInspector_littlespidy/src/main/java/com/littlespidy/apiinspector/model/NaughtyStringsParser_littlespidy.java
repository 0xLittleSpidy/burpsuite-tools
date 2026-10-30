// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the Big List of Naughty Strings (BLNS) wordlist and custom fuzzing lists.
 * Categorizes payloads into structured input validation attack techniques based on JSON category definitions.
 */
public class NaughtyStringsParser_littlespidy {

    private static final String DEFAULT_WORDLIST_PATH = "/com/littlespidy/apiinspector/wordlists/big-list-of-naughty-strings.txt";
    private static final String DEFAULT_CATEGORIES_PATH = "/com/littlespidy/apiinspector/payloads/input_validation_categories_littlespidy.json";

    public static List<InputValidationTechnique_littlespidy> loadDefaultBlnsTechniques() {
        InputStream is = NaughtyStringsParser_littlespidy.class.getResourceAsStream(DEFAULT_WORDLIST_PATH);
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

    public static List<InputValidationTechnique_littlespidy> loadCategoriesMetadata() {
        InputStream is = NaughtyStringsParser_littlespidy.class.getResourceAsStream(DEFAULT_CATEGORIES_PATH);
        if (is == null) {
            File f = new File("src/main/resources/com/littlespidy/apiinspector/payloads/input_validation_categories_littlespidy.json");
            if (!f.exists()) {
                f = new File("APIInspector_littlespidy/src/main/resources/com/littlespidy/apiinspector/payloads/input_validation_categories_littlespidy.json");
            }
            if (f.exists()) {
                try {
                    is = new FileInputStream(f);
                } catch (Exception ignored) {
                }
            }
        }

        if (is != null) {
            try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                Gson gson = new Gson();
                Type type = new TypeToken<List<InputValidationTechnique_littlespidy>>() {}.getType();
                List<InputValidationTechnique_littlespidy> loaded = gson.fromJson(reader, type);
                if (loaded != null && !loaded.isEmpty()) {
                    return loaded;
                }
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
        List<String> unwantedInterpolation = new ArrayList<>();

        for (Map.Entry<String, List<String>> entry : rawSections.entrySet()) {
            String sec = entry.getKey().toLowerCase();
            List<String> list = entry.getValue();

            if (sec.contains("msdos") || sec.contains("windows special") || sec.contains("filenames")) {
                // Omitted from retained categories per UI refinement
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
                // Omitted from retained categories per UI refinement
            } else if (sec.contains("sql") || sec.contains("server code") || sec.contains("command injection")) {
                // Omitted from retained categories per UI refinement
            } else if (sec.contains("interpolation")) {
                unwantedInterpolation.addAll(list);
            } else if (sec.contains("file inclusion") || sec.contains("xxe") || sec.contains("vulnerabilities")) {
                // Omitted from retained categories per UI refinement
            }
        }

        List<InputValidationTechnique_littlespidy> categoriesMeta = loadCategoriesMetadata();
        for (InputValidationTechnique_littlespidy meta : categoriesMeta) {
            List<String> payloads;
            switch (meta.getId()) {
                case "blns_reserved":
                    payloads = reservedStrings;
                    break;
                case "blns_numeric":
                    payloads = numericStrings;
                    break;
                case "blns_special":
                    payloads = specialChars;
                    break;
                case "blns_unicode":
                    payloads = unicodeStrings;
                    break;
                case "blns_interpolation":
                    payloads = unwantedInterpolation;
                    break;
                default:
                    payloads = meta.getSamplePayloads() != null ? meta.getSamplePayloads() : Collections.emptyList();
                    break;
            }
            techniques.add(new InputValidationTechnique_littlespidy(
                    meta.getId(),
                    meta.getCategory(),
                    meta.getDescription(),
                    payloads,
                    meta.getErrorSignatures(),
                    meta.isEnabled()
            ));
        }

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
                        "Tests keywords that may conflict with internal language interpreters (null, undef, None, True)",
                        Arrays.asList("undefined", "undef", "null", "NULL", "nil", "None", "true", "false", "True", "False"),
                        Arrays.asList("NullPointerException", "undefined", "TypeError", "ReferenceError", "NoneType")
                ),
                new InputValidationTechnique_littlespidy(
                        "blns_numeric", "BLNS: Numeric Boundaries & Extremes",
                        "Tests extreme integers, floating point errors, zero division, and NaN overflows",
                        Arrays.asList("0", "1", "-1", "1/0", "0/0", "NaN", "Infinity", "-Infinity", "0xffffffff", "99999999999999999999"),
                        Arrays.asList("NumberFormatException", "ArithmeticException", "divided by zero", "Overflow", "NaN")
                ),
                new InputValidationTechnique_littlespidy(
                        "blns_special", "BLNS: Special Characters & Quotation Quirks",
                        "Tests misplaced quotes, delimiters, and C0/C1 non-whitespace control codes",
                        Arrays.asList("'", "\"", ";", "--", "/*", "*/", "||", "&&"),
                        Arrays.asList("syntax error", "parse error", "unterminated string", "unclosed quotation", "unexpected token")
                ),
                new InputValidationTechnique_littlespidy(
                        "blns_unicode", "BLNS: Unicode & Encoding Edge-Cases",
                        "Tests two-byte characters, case expansion, right-to-left overrides, and surrogate pairs",
                        Arrays.asList("Unicode", "U+FEFF", "%C0%AF"),
                        Arrays.asList("CharacterCodingException", "MalformedInputException", "UnicodeDecodeError", "utf8", "encoding error")
                ),
                new InputValidationTechnique_littlespidy(
                        "blns_interpolation", "BLNS: Format Strings & Unwanted Interpolation",
                        "Tests printf format string specifiers and accidental shell evaluation (%s, %x, %n)",
                        Arrays.asList("%s", "%x", "%n", "${7*7}"),
                        Collections.emptyList()
                )
        );
    }
}
