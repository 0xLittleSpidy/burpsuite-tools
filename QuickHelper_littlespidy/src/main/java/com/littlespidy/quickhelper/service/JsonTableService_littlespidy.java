// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.littlespidy.quickhelper.model.JsonTableData_littlespidy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service to parse, inspect, and convert JSON response payloads into tabular data structures.
 */
public class JsonTableService_littlespidy {

    private static final Gson GSON_PRETTY = new GsonBuilder().setPrettyPrinting().create();

    private static final String[] PRIMARY_ARRAY_KEYS = {
            "data", "items", "results", "users", "records", "entries", "rows", "list", "logs", "values"
    };

    /**
     * Checks if a response body or content-type looks like valid JSON.
     */
    public boolean isJsonCandidate(String body, String contentType) {
        if (contentType != null && contentType.toLowerCase().contains("json")) {
            return true;
        }
        if (body == null) {
            return false;
        }
        String trimmed = body.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    /**
     * Parses the response body into a structured JsonTableData model.
     */
    public JsonTableData_littlespidy parseJsonToTable(String jsonBody) {
        if (jsonBody == null || jsonBody.trim().isEmpty()) {
            return JsonTableData_littlespidy.empty("Empty response body");
        }

        JsonElement root;
        try {
            root = JsonParser.parseString(jsonBody);
        } catch (Exception e) {
            return JsonTableData_littlespidy.empty("Invalid JSON: " + e.getMessage());
        }

        if (root.isJsonArray()) {
            return parseArray(root.getAsJsonArray(), "Root JSON Array");
        } else if (root.isJsonObject()) {
            JsonObject obj = root.getAsJsonObject();

            // Check if there is a primary container array of objects (e.g. { "data": [ ... ] })
            for (String key : PRIMARY_ARRAY_KEYS) {
                if (obj.has(key) && obj.get(key).isJsonArray()) {
                    JsonArray arr = obj.getAsJsonArray(key);
                    if (arr.size() > 0 && arr.get(0).isJsonObject()) {
                        return parseArray(arr, "JSON Array ('" + key + "')");
                    }
                }
            }

            // Check any other key holding an array of objects
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                if (entry.getValue().isJsonArray()) {
                    JsonArray arr = entry.getValue().getAsJsonArray();
                    if (arr.size() > 0 && arr.get(0).isJsonObject()) {
                        return parseArray(arr, "JSON Array ('" + entry.getKey() + "')");
                    }
                }
            }

            // Otherwise, flatten object to 2-column table
            return parseFlattenedObject(obj);
        } else {
            // Single primitive
            List<String> cols = List.of("Value");
            List<List<String>> rows = List.of(List.of(formatPrimitive(root.getAsJsonPrimitive())));
            return new JsonTableData_littlespidy("Single Value", cols, rows, List.of(root), false);
        }
    }

    private JsonTableData_littlespidy parseArray(JsonArray array, String contextTitle) {
        if (array.size() == 0) {
            return new JsonTableData_littlespidy(contextTitle + " (Empty)", List.of("Result"), List.of(List.of("(Empty Array)")), List.of(array), true);
        }

        boolean allObjects = true;
        Set<String> columnKeySet = new LinkedHashSet<>();
        List<JsonElement> rawElements = new ArrayList<>();

        for (int i = 0; i < array.size(); i++) {
            JsonElement el = array.get(i);
            rawElements.add(el);
            if (el.isJsonObject()) {
                JsonObject o = el.getAsJsonObject();
                for (String k : o.keySet()) {
                    columnKeySet.add(k);
                }
            } else {
                allObjects = false;
            }
        }

        if (allObjects && !columnKeySet.isEmpty()) {
            List<String> columns = new ArrayList<>(columnKeySet);
            List<List<String>> rows = new ArrayList<>();

            for (int i = 0; i < array.size(); i++) {
                JsonObject o = array.get(i).getAsJsonObject();
                List<String> row = new ArrayList<>(columns.size());
                for (String col : columns) {
                    if (o.has(col)) {
                        row.add(formatElement(o.get(col)));
                    } else {
                        row.add("");
                    }
                }
                rows.add(row);
            }

            String title = contextTitle + " (" + rows.size() + " items, " + columns.size() + " columns)";
            return new JsonTableData_littlespidy(title, columns, rows, rawElements, true);
        } else {
            // Primitives or mixed array
            List<String> columns = List.of("Index", "Value");
            List<List<String>> rows = new ArrayList<>();
            for (int i = 0; i < array.size(); i++) {
                rows.add(List.of(String.valueOf(i + 1), formatElement(array.get(i))));
            }
            String title = contextTitle + " (" + rows.size() + " items)";
            return new JsonTableData_littlespidy(title, columns, rows, rawElements, true);
        }
    }

    private JsonTableData_littlespidy parseFlattenedObject(JsonObject obj) {
        Map<String, String> flatMap = new LinkedHashMap<>();
        flattenJsonObject("", obj, flatMap);

        List<String> columns = List.of("Key / JSON Path", "Value");
        List<List<String>> rows = new ArrayList<>();
        List<JsonElement> rawElements = new ArrayList<>();

        for (Map.Entry<String, String> entry : flatMap.entrySet()) {
            rows.add(List.of(entry.getKey(), entry.getValue()));
        }
        rawElements.add(obj);

        String title = "JSON Object (" + rows.size() + " fields)";
        return new JsonTableData_littlespidy(title, columns, rows, rawElements, false);
    }

    private void flattenJsonObject(String prefix, JsonObject obj, Map<String, String> result) {
        for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            JsonElement val = entry.getValue();
            if (val.isJsonObject()) {
                flattenJsonObject(key, val.getAsJsonObject(), result);
            } else if (val.isJsonArray()) {
                JsonArray arr = val.getAsJsonArray();
                if (arr.size() == 0) {
                    result.put(key, "[]");
                } else if (arr.get(0).isJsonPrimitive()) {
                    result.put(key, formatElement(arr));
                } else {
                    for (int i = 0; i < arr.size(); i++) {
                        JsonElement item = arr.get(i);
                        if (item.isJsonObject()) {
                            flattenJsonObject(key + "[" + i + "]", item.getAsJsonObject(), result);
                        } else {
                            result.put(key + "[" + i + "]", formatElement(item));
                        }
                    }
                }
            } else {
                result.put(key, formatElement(val));
            }
        }
    }

    public String formatElement(JsonElement el) {
        if (el == null || el.isJsonNull()) {
            return "null";
        }
        if (el.isJsonPrimitive()) {
            return formatPrimitive(el.getAsJsonPrimitive());
        }
        return el.toString();
    }

    private String formatPrimitive(JsonPrimitive p) {
        if (p.isBoolean()) {
            return String.valueOf(p.getAsBoolean());
        }
        if (p.isNumber()) {
            return p.getAsString();
        }
        return p.getAsString();
    }

    public String formatPretty(JsonElement el) {
        if (el == null) return "";
        return GSON_PRETTY.toJson(el);
    }

    /**
     * Converts columns and rows into RFC 4180 CSV format.
     */
    public String toCsv(List<String> columns, List<List<String>> rows) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < columns.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(escapeCsv(columns.get(i)));
        }
        sb.append("\n");

        for (List<String> row : rows) {
            for (int i = 0; i < row.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(escapeCsv(row.get(i)));
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    private String escapeCsv(String val) {
        if (val == null) return "\"\"";
        String escaped = val.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }
}
