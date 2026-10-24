// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.inql;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.*;

public class CycleScanner_littlespidy {

    public static class CycleFinding {
        public final List<String> path;
        public final String rootType;
        public final String recursionQuery;

        public CycleFinding(List<String> path, String rootType, String recursionQuery) {
            this.path = path;
            this.rootType = rootType;
            this.recursionQuery = recursionQuery;
        }

        public String getPathDisplay() {
            return String.join(" -> ", path);
        }
    }

    public static List<CycleFinding> detectCycles(String schemaJson, int maxDepth) {
        List<CycleFinding> results = new ArrayList<>();
        if (schemaJson == null || schemaJson.trim().isEmpty()) {
            return results;
        }

        try {
            JsonObject root = JsonParser.parseString(schemaJson).getAsJsonObject();
            JsonObject schemaObj = root.has("data") && root.getAsJsonObject("data").has("__schema")
                    ? root.getAsJsonObject("data").getAsJsonObject("__schema")
                    : (root.has("__schema") ? root.getAsJsonObject("__schema") : root);

            if (!schemaObj.has("types")) {
                return results;
            }

            // Build map of TypeName -> List of (fieldName, targetTypeName)
            Map<String, Map<String, String>> typeGraph = new HashMap<>();

            JsonArray types = schemaObj.getAsJsonArray("types");
            for (JsonElement tEl : types) {
                JsonObject typeObj = tEl.getAsJsonObject();
                String typeName = typeObj.has("name") && !typeObj.get("name").isJsonNull()
                        ? typeObj.get("name").getAsString() : "";

                if (typeName.startsWith("__") || typeName.isEmpty()) continue;

                if (typeObj.has("fields") && !typeObj.get("fields").isJsonNull()) {
                    Map<String, String> fieldMap = new LinkedHashMap<>();
                    JsonArray fields = typeObj.getAsJsonArray("fields");
                    for (JsonElement fEl : fields) {
                        JsonObject fObj = fEl.getAsJsonObject();
                        String fieldName = fObj.has("name") ? fObj.get("name").getAsString() : "";
                        String targetType = unwrapTypeName(fObj.get("type"));
                        if (!targetType.isEmpty() && !isScalar(targetType)) {
                            fieldMap.put(fieldName, targetType);
                        }
                    }
                    typeGraph.put(typeName, fieldMap);
                }
            }

            // Run DFS on each type
            Set<String> seenCycles = new HashSet<>();
            for (String startType : typeGraph.keySet()) {
                List<String> currentPath = new ArrayList<>();
                currentPath.add(startType);
                dfs(startType, startType, typeGraph, currentPath, seenCycles, results, maxDepth);
            }
        } catch (Exception ignored) {}

        return results;
    }

    private static void dfs(String rootType, String currentType, Map<String, Map<String, String>> graph,
                            List<String> path, Set<String> seenCycles, List<CycleFinding> results, int maxDepth) {
        if (path.size() > maxDepth) return;

        Map<String, String> neighbors = graph.get(currentType);
        if (neighbors == null) return;

        for (Map.Entry<String, String> entry : neighbors.entrySet()) {
            String fieldName = entry.getKey();
            String targetType = entry.getValue();

            if (targetType.equals(rootType)) {
                // Cycle found
                List<String> cyclePath = new ArrayList<>(path);
                cyclePath.add(targetType);
                String signature = String.join("->", cyclePath);

                if (!seenCycles.contains(signature)) {
                    seenCycles.add(signature);
                    String cyclicQuery = generateRecursiveQuery(cyclePath, 8);
                    results.add(new CycleFinding(cyclePath, rootType, cyclicQuery));
                }
                return;
            }

            if (!path.contains(targetType)) {
                path.add(targetType);
                dfs(rootType, targetType, graph, path, seenCycles, results, maxDepth);
                path.remove(path.size() - 1);
            }
        }
    }

    private static String generateRecursiveQuery(List<String> path, int depth) {
        if (path.size() < 2) return "query { __typename }";
        StringBuilder sb = new StringBuilder();
        sb.append("query CyclicAmplificationDoS {\n");

        int indent = 2;
        for (int d = 0; d < depth; d++) {
            for (int i = 0; i < path.size() - 1; i++) {
                sb.append(" ".repeat(indent))
                        .append(path.get(i).toLowerCase()).append(" {\n");
                indent += 2;
            }
        }

        sb.append(" ".repeat(indent)).append("id\n");

        while (indent > 2) {
            indent -= 2;
            sb.append(" ".repeat(indent)).append("}\n");
        }
        sb.append("}\n");
        return sb.toString();
    }

    private static boolean isScalar(String typeName) {
        return "String".equals(typeName) || "Int".equals(typeName) ||
                "Float".equals(typeName) || "Boolean".equals(typeName) ||
                "ID".equals(typeName);
    }

    private static String unwrapTypeName(JsonElement typeEl) {
        if (typeEl == null || !typeEl.isJsonObject()) return "";
        JsonObject obj = typeEl.getAsJsonObject();
        if (obj.has("name") && !obj.get("name").isJsonNull()) {
            return obj.get("name").getAsString();
        }
        if (obj.has("ofType") && !obj.get("ofType").isJsonNull()) {
            return unwrapTypeName(obj.get("ofType"));
        }
        return "";
    }
}
