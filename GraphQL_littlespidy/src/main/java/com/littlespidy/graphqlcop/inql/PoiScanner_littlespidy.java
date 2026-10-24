// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.inql;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

public class PoiScanner_littlespidy {
    private static final Map<String, List<Pattern>> CATEGORY_PATTERNS = new LinkedHashMap<>();

    static {
        loadKeywords();
    }

    private static void loadKeywords() {
        try (InputStream is = PoiScanner_littlespidy.class.getResourceAsStream("/inql/keywords.json")) {
            if (is != null) {
                JsonArray arr = JsonParser.parseReader(new InputStreamReader(is, StandardCharsets.UTF_8)).getAsJsonArray();
                for (JsonElement el : arr) {
                    JsonObject obj = el.getAsJsonObject();
                    String name = obj.get("name").getAsString();
                    if ("Priviliged".equalsIgnoreCase(name)) {
                        name = "Privileged";
                    }
                    List<Pattern> patterns = new ArrayList<>();
                    JsonArray kwArr = obj.getAsJsonArray("keywords");
                    for (JsonElement kw : kwArr) {
                        try {
                            patterns.add(Pattern.compile(kw.getAsString(), Pattern.CASE_INSENSITIVE));
                        } catch (Exception ignored) {}
                    }
                    CATEGORY_PATTERNS.put(name, patterns);
                }
            }
        } catch (Exception ignored) {}

        if (CATEGORY_PATTERNS.isEmpty()) {
            addFallbackPatterns();
        }
    }

    private static void addFallbackPatterns() {
        CATEGORY_PATTERNS.put("Auth", Arrays.asList(
                Pattern.compile("token|auth|session|key|secret|password|pwd|login|credential", Pattern.CASE_INSENSITIVE)
        ));
        CATEGORY_PATTERNS.put("Privileged", Arrays.asList(
                Pattern.compile("admin|root|super|sudo|privileged|role|permission|grant", Pattern.CASE_INSENSITIVE)
        ));
        CATEGORY_PATTERNS.put("PII", Arrays.asList(
                Pattern.compile("email|phone|ssn|dob|passport|address|firstname|lastname", Pattern.CASE_INSENSITIVE)
        ));
        CATEGORY_PATTERNS.put("Payment", Arrays.asList(
                Pattern.compile("card|cvv|billing|credit|invoice|stripe|paypal|account_number", Pattern.CASE_INSENSITIVE)
        ));
        CATEGORY_PATTERNS.put("Database", Arrays.asList(
                Pattern.compile("query|sql|table|db|dump|database|raw", Pattern.CASE_INSENSITIVE)
        ));
        CATEGORY_PATTERNS.put("Debugging", Arrays.asList(
                Pattern.compile("debug|test|trace|internal|benchmark|metrics|log", Pattern.CASE_INSENSITIVE)
        ));
        CATEGORY_PATTERNS.put("Files", Arrays.asList(
                Pattern.compile("file|upload|path|storage|s3|bucket|download|attachment", Pattern.CASE_INSENSITIVE)
        ));
    }

    public static List<PoiFinding_littlespidy> scanSchema(String schemaJson) {
        List<PoiFinding_littlespidy> findings = new ArrayList<>();
        if (schemaJson == null || schemaJson.trim().isEmpty()) {
            return findings;
        }

        try {
            JsonObject root = JsonParser.parseString(schemaJson).getAsJsonObject();
            JsonObject schemaObj = root.has("data") && root.getAsJsonObject("data").has("__schema")
                    ? root.getAsJsonObject("data").getAsJsonObject("__schema")
                    : (root.has("__schema") ? root.getAsJsonObject("__schema") : root);

            if (!schemaObj.has("types")) {
                return findings;
            }

            JsonArray types = schemaObj.getAsJsonArray("types");
            for (JsonElement tEl : types) {
                JsonObject typeObj = tEl.getAsJsonObject();
                String typeName = typeObj.has("name") && !typeObj.get("name").isJsonNull()
                        ? typeObj.get("name").getAsString() : "";

                // Skip built-in introspection metadata types
                if (typeName.startsWith("__")) {
                    continue;
                }

                if (typeObj.has("fields") && !typeObj.get("fields").isJsonNull()) {
                    JsonArray fields = typeObj.getAsJsonArray("fields");
                    for (JsonElement fEl : fields) {
                        JsonObject fObj = fEl.getAsJsonObject();
                        String fieldName = fObj.has("name") ? fObj.get("name").getAsString() : "";
                        String returnType = unwrapTypeName(fObj.get("type"));

                        // Test field against categories
                        for (Map.Entry<String, List<Pattern>> entry : CATEGORY_PATTERNS.entrySet()) {
                            String category = entry.getKey();
                            for (Pattern p : entry.getValue()) {
                                if (p.matcher(fieldName).find() || p.matcher(typeName).find()) {
                                    findings.add(new PoiFinding_littlespidy(
                                            category,
                                            typeName,
                                            fieldName,
                                            returnType,
                                            p.pattern()
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }

    private static String unwrapTypeName(JsonElement typeEl) {
        if (typeEl == null || !typeEl.isJsonObject()) return "Unknown";
        JsonObject obj = typeEl.getAsJsonObject();
        if (obj.has("name") && !obj.get("name").isJsonNull()) {
            return obj.get("name").getAsString();
        }
        if (obj.has("ofType") && !obj.get("ofType").isJsonNull()) {
            return unwrapTypeName(obj.get("ofType"));
        }
        return "Unknown";
    }
}
