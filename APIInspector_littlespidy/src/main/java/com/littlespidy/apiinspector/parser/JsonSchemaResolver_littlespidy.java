// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import com.google.gson.*;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;

import java.util.*;

/**
 * Utility for resolving JSON Schema references ($ref), composite schemas (allOf, anyOf, oneOf),
 * and generating realistic JSON body samples and extracted body parameters for OpenAPI and Swagger.
 */
public class JsonSchemaResolver_littlespidy {

    private static final int MAX_DEPTH = 6;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private JsonSchemaResolver_littlespidy() {
    }

    /**
     * Resolves a JSON reference (e.g. "#/components/schemas/User" or "#/definitions/User")
     * against the root specification JSON object.
     */
    public static JsonObject resolveRef(JsonObject root, String ref) {
        if (root == null || ref == null || ref.isBlank()) {
            return null;
        }

        String pointer = ref.trim();
        if (pointer.startsWith("#/")) {
            pointer = pointer.substring(2);
        } else if (pointer.startsWith("#")) {
            pointer = pointer.substring(1);
        }

        String[] tokens = pointer.split("/");
        JsonElement current = root;

        for (String token : tokens) {
            if (token.isEmpty()) continue;
            // Unescape JSON Pointer tokens (~1 is '/', ~0 is '~')
            String unescaped = token.replace("~1", "/").replace("~0", "~");
            if (current != null && current.isJsonObject()) {
                current = current.getAsJsonObject().get(unescaped);
            } else {
                return null;
            }
        }

        return (current != null && current.isJsonObject()) ? current.getAsJsonObject() : null;
    }

    /**
     * Generates a realistic sample JsonElement from a JSON Schema, resolving any $ref references,
     * merging allOf schemas, and extracting parameter names and sample values into bodyParams.
     */
    public static JsonElement generateSample(
            JsonObject root,
            JsonObject schema,
            Map<String, String> bodyParams,
            Set<String> visitedRefs,
            int depth) {

        if (schema == null || depth > MAX_DEPTH) {
            return new JsonObject();
        }

        // 1. Handle $ref
        if (schema.has("$ref") && schema.get("$ref").isJsonPrimitive()) {
            String ref = schema.get("$ref").getAsString();
            if (visitedRefs.contains(ref)) {
                return new JsonObject(); // Prevent circular reference loops
            }
            Set<String> nextVisited = new HashSet<>(visitedRefs);
            nextVisited.add(ref);

            JsonObject resolved = resolveRef(root, ref);
            if (resolved != null) {
                return generateSample(root, resolved, bodyParams, nextVisited, depth + 1);
            }
            return new JsonObject();
        }

        // 2. Handle allOf (merge properties)
        if (schema.has("allOf") && schema.get("allOf").isJsonArray()) {
            JsonObject merged = new JsonObject();
            JsonObject mergedProperties = new JsonObject();

            for (JsonElement subEl : schema.getAsJsonArray("allOf")) {
                if (!subEl.isJsonObject()) continue;
                JsonObject subObj = subEl.getAsJsonObject();
                if (subObj.has("$ref")) {
                    JsonObject res = resolveRef(root, subObj.get("$ref").getAsString());
                    if (res != null) subObj = res;
                }
                if (subObj.has("properties") && subObj.get("properties").isJsonObject()) {
                    JsonObject props = subObj.getAsJsonObject("properties");
                    for (Map.Entry<String, JsonElement> pEntry : props.entrySet()) {
                        mergedProperties.add(pEntry.getKey(), pEntry.getValue());
                    }
                }
            }

            if (!mergedProperties.isEmpty()) {
                merged.add("type", new JsonPrimitive("object"));
                merged.add("properties", mergedProperties);
                return generateSample(root, merged, bodyParams, visitedRefs, depth);
            }
        }

        // 3. Handle anyOf / oneOf (select first valid variant)
        if (schema.has("anyOf") && schema.get("anyOf").isJsonArray()) {
            JsonArray anyOf = schema.getAsJsonArray("anyOf");
            if (!anyOf.isEmpty() && anyOf.get(0).isJsonObject()) {
                return generateSample(root, anyOf.get(0).getAsJsonObject(), bodyParams, visitedRefs, depth + 1);
            }
        }
        if (schema.has("oneOf") && schema.get("oneOf").isJsonArray()) {
            JsonArray oneOf = schema.getAsJsonArray("oneOf");
            if (!oneOf.isEmpty() && oneOf.get(0).isJsonObject()) {
                return generateSample(root, oneOf.get(0).getAsJsonObject(), bodyParams, visitedRefs, depth + 1);
            }
        }

        // 4. Handle direct example at schema level
        if (schema.has("example")) {
            JsonElement ex = schema.get("example");
            extractParamsFromJsonElement(ex, "", bodyParams);
            return ex;
        }

        // 5. Determine type
        String type = "object";
        if (schema.has("type") && schema.get("type").isJsonPrimitive()) {
            type = schema.get("type").getAsString().toLowerCase(Locale.ROOT);
        } else if (schema.has("properties")) {
            type = "object";
        } else if (schema.has("items")) {
            type = "array";
        }

        // 6. Handle array type
        if ("array".equals(type) || schema.has("items")) {
            JsonArray array = new JsonArray();
            if (schema.has("items") && schema.get("items").isJsonObject()) {
                JsonObject itemSchema = schema.getAsJsonObject("items");
                JsonElement itemSample = generateSample(root, itemSchema, bodyParams, visitedRefs, depth + 1);
                array.add(itemSample);
            } else {
                array.add(new JsonPrimitive("sample"));
            }
            return array;
        }

        // 7. Handle object type
        if ("object".equals(type) || schema.has("properties")) {
            JsonObject obj = new JsonObject();
            if (schema.has("properties") && schema.get("properties").isJsonObject()) {
                JsonObject props = schema.getAsJsonObject("properties");
                for (Map.Entry<String, JsonElement> propEntry : props.entrySet()) {
                    String propName = propEntry.getKey();
                    if (!propEntry.getValue().isJsonObject()) {
                        obj.addProperty(propName, "sample");
                        if (bodyParams != null) bodyParams.put(propName, "sample");
                        continue;
                    }

                    JsonObject propSchema = propEntry.getValue().getAsJsonObject();
                    JsonElement propVal = generateSample(root, propSchema, bodyParams, visitedRefs, depth + 1);
                    obj.add(propName, propVal);

                    // Record parameter in bodyParams
                    if (bodyParams != null) {
                        String sampleStr = propVal.isJsonPrimitive() ? propVal.getAsString() : GSON.toJson(propVal);
                        bodyParams.put(propName, sampleStr);
                    }
                }
            }
            return obj;
        }

        // 8. Handle primitive types
        return generatePrimitiveSample(schema);
    }

    private static JsonElement generatePrimitiveSample(JsonObject schema) {
        String type = schema.has("type") && schema.get("type").isJsonPrimitive()
                ? schema.get("type").getAsString().toLowerCase(Locale.ROOT)
                : "string";

        if (schema.has("example")) {
            return schema.get("example");
        }
        if (schema.has("default")) {
            return schema.get("default");
        }
        if (schema.has("enum") && schema.get("enum").isJsonArray()) {
            JsonArray enums = schema.getAsJsonArray("enum");
            if (!enums.isEmpty()) {
                return enums.get(0);
            }
        }

        if ("integer".equals(type)) {
            return new JsonPrimitive(1);
        } else if ("number".equals(type)) {
            return new JsonPrimitive(1.0);
        } else if ("boolean".equals(type)) {
            return new JsonPrimitive(true);
        } else {
            // String with format support
            String format = schema.has("format") && schema.get("format").isJsonPrimitive()
                    ? schema.get("format").getAsString().toLowerCase(Locale.ROOT)
                    : "";

            switch (format) {
                case "email":
                    return new JsonPrimitive("user@example.com");
                case "uuid":
                    return new JsonPrimitive("123e4567-e89b-12d3-a456-426614174000");
                case "date":
                    return new JsonPrimitive("2026-01-15");
                case "date-time":
                    return new JsonPrimitive("2026-01-15T10:00:00Z");
                case "uri":
                case "url":
                    return new JsonPrimitive("https://example.com");
                case "byte":
                case "binary":
                    return new JsonPrimitive("dGVzdA==");
                case "password":
                    return new JsonPrimitive("password123");
                default:
                    return new JsonPrimitive("sample");
            }
        }
    }

    /**
     * Extracts parameter keys and sample values from an existing JsonElement (e.g. from examples).
     */
    public static void extractParamsFromJsonElement(JsonElement element, String prefix, Map<String, String> bodyParams) {
        if (element == null || bodyParams == null) return;

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String key = entry.getKey();
                String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
                JsonElement val = entry.getValue();

                if (val.isJsonPrimitive()) {
                    bodyParams.put(key, val.getAsString());
                    if (!prefix.isEmpty()) {
                        bodyParams.put(fullKey, val.getAsString());
                    }
                } else if (val.isJsonObject()) {
                    bodyParams.put(key, GSON.toJson(val));
                    extractParamsFromJsonElement(val, fullKey, bodyParams);
                } else if (val.isJsonArray()) {
                    bodyParams.put(key, GSON.toJson(val));
                }
            }
        }
    }

    /**
     * Extracts request body sample and parameters from an OpenAPI 3.x operation requestBody object.
     */
    public static void extractOpenAPIRequestBody(
            JsonObject root,
            JsonObject reqBodyObj,
            DiscoveredEndpoint_littlespidy ep,
            Gson gson) {

        if (reqBodyObj == null || ep == null) return;

        JsonObject actualBody = reqBodyObj;
        if (reqBodyObj.has("$ref") && reqBodyObj.get("$ref").isJsonPrimitive()) {
            JsonObject resolved = resolveRef(root, reqBodyObj.get("$ref").getAsString());
            if (resolved != null) {
                actualBody = resolved;
            }
        }

        if (!actualBody.has("content") || !actualBody.get("content").isJsonObject()) {
            return;
        }

        JsonObject content = actualBody.getAsJsonObject("content");

        // Prefer application/json, then application/x-www-form-urlencoded, multipart/form-data, or first available
        String chosenContentType = null;
        JsonObject chosenMedia = null;

        for (String candidate : new String[]{"application/json", "application/x-www-form-urlencoded", "multipart/form-data", "*/*"}) {
            if (content.has(candidate) && content.get(candidate).isJsonObject()) {
                chosenContentType = candidate;
                chosenMedia = content.getAsJsonObject(candidate);
                break;
            }
        }

        if (chosenMedia == null) {
            for (Map.Entry<String, JsonElement> entry : content.entrySet()) {
                if (entry.getValue().isJsonObject()) {
                    chosenContentType = entry.getKey();
                    chosenMedia = entry.getValue().getAsJsonObject();
                    break;
                }
            }
        }

        if (chosenContentType == null || chosenMedia == null) {
            return;
        }

        ep.setContentType(chosenContentType);
        Map<String, String> bodyParams = ep.getBodyParams();

        // Check for media type example
        if (chosenMedia.has("example")) {
            JsonElement ex = chosenMedia.get("example");
            ep.setRequestBodySample(gson.toJson(ex));
            extractParamsFromJsonElement(ex, "", bodyParams);
            return;
        }

        // Check for media type examples
        if (chosenMedia.has("examples") && chosenMedia.get("examples").isJsonObject()) {
            JsonObject examplesObj = chosenMedia.getAsJsonObject("examples");
            for (Map.Entry<String, JsonElement> exEntry : examplesObj.entrySet()) {
                if (exEntry.getValue().isJsonObject()) {
                    JsonObject exVal = exEntry.getValue().getAsJsonObject();
                    if (exVal.has("value")) {
                        JsonElement val = exVal.get("value");
                        ep.setRequestBodySample(gson.toJson(val));
                        extractParamsFromJsonElement(val, "", bodyParams);
                        return;
                    }
                }
            }
        }

        // Generate from schema
        if (chosenMedia.has("schema") && chosenMedia.get("schema").isJsonObject()) {
            JsonObject schemaObj = chosenMedia.getAsJsonObject("schema");
            JsonElement sampleElement = generateSample(root, schemaObj, bodyParams, new HashSet<>(), 0);

            if (chosenContentType.contains("x-www-form-urlencoded")) {
                StringBuilder formBody = new StringBuilder();
                if (sampleElement.isJsonObject()) {
                    for (Map.Entry<String, JsonElement> entry : sampleElement.getAsJsonObject().entrySet()) {
                        if (formBody.length() > 0) formBody.append("&");
                        String v = entry.getValue().isJsonPrimitive() ? entry.getValue().getAsString() : "sample";
                        formBody.append(entry.getKey()).append("=").append(v);
                    }
                }
                ep.setRequestBodySample(formBody.toString());
            } else {
                ep.setRequestBodySample(gson.toJson(sampleElement));
            }
        }
    }
}
