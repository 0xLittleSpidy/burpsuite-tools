// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import com.google.gson.*;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import org.yaml.snakeyaml.Yaml;

import java.util.*;

/**
 * Parser for OpenAPI 3.0.x and 3.1.x specifications in JSON or YAML format.
 */
public class OpenAPIParser_littlespidy implements APIParser_littlespidy {

    private final Gson gson = new Gson();

    @Override
    public boolean canParse(String content) {
        if (content == null || content.isBlank()) return false;
        try {
            JsonObject root = parseRootObject(content);
            if (root != null && root.has("openapi")) {
                String openapi = root.get("openapi").getAsString();
                return openapi != null && (openapi.startsWith("3.") || openapi.startsWith("3"));
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    @Override
    public ParseResult_littlespidy parse(String content, String sourceLocation, String sourceType) {
        try {
            JsonObject root = parseRootObject(content);
            if (root == null || !root.has("openapi")) {
                return ParseResult_littlespidy.failure("Invalid OpenAPI specification: missing 'openapi' version attribute.");
            }

            String openapiVersion = root.get("openapi").getAsString();
            String title = "OpenAPI Collection";
            if (root.has("info") && root.get("info").isJsonObject()) {
                JsonObject info = root.getAsJsonObject("info");
                if (info.has("title") && !info.get("title").getAsString().isBlank()) {
                    title = info.get("title").getAsString();
                }
            }

            ImportedCollection_littlespidy collection = new ImportedCollection_littlespidy(
                    title,
                    "OpenAPI " + openapiVersion,
                    sourceType,
                    sourceLocation
            );

            // Extract Base URL from servers
            String targetBaseUrl = "";
            if (root.has("servers") && root.get("servers").isJsonArray()) {
                JsonArray servers = root.getAsJsonArray("servers");
                if (!servers.isEmpty() && servers.get(0).isJsonObject()) {
                    JsonObject firstServer = servers.get(0).getAsJsonObject();
                    if (firstServer.has("url")) {
                        targetBaseUrl = firstServer.get("url").getAsString();
                    }
                }
            }
            collection.setTargetBaseUrl(targetBaseUrl);

            // Extract Endpoints from paths
            List<DiscoveredEndpoint_littlespidy> endpoints = new ArrayList<>();
            if (root.has("paths") && root.get("paths").isJsonObject()) {
                JsonObject pathsObj = root.getAsJsonObject("paths");
                for (Map.Entry<String, JsonElement> pathEntry : pathsObj.entrySet()) {
                    String path = pathEntry.getKey();
                    if (!pathEntry.getValue().isJsonObject()) continue;
                    JsonObject pathItem = pathEntry.getValue().getAsJsonObject();

                    // Common path parameters
                    Map<String, String> commonPathParams = new LinkedHashMap<>();
                    Map<String, String> commonQueryParams = new LinkedHashMap<>();
                    Map<String, String> commonHeaders = new LinkedHashMap<>();
                    if (pathItem.has("parameters") && pathItem.get("parameters").isJsonArray()) {
                        extractParameters(pathItem.getAsJsonArray("parameters"), commonPathParams, commonQueryParams, commonHeaders);
                    }

                    for (String method : new String[]{"get", "post", "put", "delete", "patch", "options", "head"}) {
                        if (pathItem.has(method) && pathItem.get(method).isJsonObject()) {
                            JsonObject op = pathItem.getAsJsonObject(method);
                            DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy();
                            ep.setMethod(method.toUpperCase(Locale.ROOT));
                            ep.setPath(path);

                            if (op.has("summary") && !op.get("summary").isJsonNull()) {
                                ep.setSummary(op.get("summary").getAsString());
                            } else if (op.has("operationId") && !op.get("operationId").isJsonNull()) {
                                ep.setSummary(op.get("operationId").getAsString());
                            }

                            if (op.has("description") && !op.get("description").isJsonNull()) {
                                ep.setDescription(op.get("description").getAsString());
                            }

                            Map<String, String> pathParams = new LinkedHashMap<>(commonPathParams);
                            Map<String, String> queryParams = new LinkedHashMap<>(commonQueryParams);
                            Map<String, String> headers = new LinkedHashMap<>(commonHeaders);

                            if (op.has("parameters") && op.get("parameters").isJsonArray()) {
                                extractParameters(op.getAsJsonArray("parameters"), pathParams, queryParams, headers);
                            }
                            ep.setPathParams(pathParams);
                            ep.setQueryParams(queryParams);
                            ep.setHeaders(headers);

                            // Request body
                            if (op.has("requestBody") && op.get("requestBody").isJsonObject()) {
                                JsonSchemaResolver_littlespidy.extractOpenAPIRequestBody(root, op.getAsJsonObject("requestBody"), ep, gson);
                            }

                            // Security / Auth
                            if (op.has("security") && op.get("security").isJsonArray()) {
                                JsonArray sec = op.getAsJsonArray("security");
                                ep.setRequiresAuth(!sec.isEmpty());
                                for (JsonElement se : sec) {
                                    if (se.isJsonObject()) {
                                        ep.getAuthSchemes().addAll(se.getAsJsonObject().keySet());
                                    }
                                }
                            } else if (root.has("security") && root.get("security").isJsonArray()) {
                                JsonArray sec = root.getAsJsonArray("security");
                                ep.setRequiresAuth(!sec.isEmpty());
                                for (JsonElement se : sec) {
                                    if (se.isJsonObject()) {
                                        ep.getAuthSchemes().addAll(se.getAsJsonObject().keySet());
                                    }
                                }
                            }

                            endpoints.add(ep);
                        }
                    }
                }
            }

            collection.setEndpoints(endpoints);
            collection.setImportStatus("Parsed Successfully (" + endpoints.size() + " endpoints)");
            return ParseResult_littlespidy.success(collection);

        } catch (Exception ex) {
            return ParseResult_littlespidy.failure("OpenAPI parsing error: " + ex.getMessage());
        }
    }

    private void extractParameters(JsonArray paramArray, Map<String, String> pathParams, Map<String, String> queryParams, Map<String, String> headers) {
        for (JsonElement p : paramArray) {
            if (!p.isJsonObject()) continue;
            JsonObject pObj = p.getAsJsonObject();
            String name = pObj.has("name") ? pObj.get("name").getAsString() : "";
            String in = pObj.has("in") ? pObj.get("in").getAsString().toLowerCase(Locale.ROOT) : "";
            String example = "1";
            if (pObj.has("example")) {
                example = pObj.get("example").getAsString();
            } else if (pObj.has("schema") && pObj.get("schema").isJsonObject()) {
                JsonObject s = pObj.getAsJsonObject("schema");
                if (s.has("example")) example = s.get("example").getAsString();
                else if (s.has("default")) example = s.get("default").getAsString();
                else if (s.has("type") && "string".equalsIgnoreCase(s.get("type").getAsString())) example = "sample";
            }

            if ("path".equals(in)) {
                pathParams.put(name, example);
            } else if ("query".equals(in)) {
                queryParams.put(name, example);
            } else if ("header".equals(in)) {
                headers.put(name, example);
            }
        }
    }

    private String generateSampleFromSchema(JsonObject schema) {
        if (schema == null) return "{}";
        JsonElement el = JsonSchemaResolver_littlespidy.generateSample(null, schema, null, new HashSet<>(), 0);
        return gson.toJson(el);
    }

    private JsonObject parseRootObject(String content) {
        String trimmed = content.trim();
        if (trimmed.startsWith("{")) {
            JsonElement elem = JsonParser.parseString(trimmed);
            if (elem.isJsonObject()) return elem.getAsJsonObject();
        }
        Yaml yaml = new Yaml();
        Object loaded = yaml.load(content);
        if (loaded instanceof Map) {
            JsonElement elem = gson.toJsonTree(loaded);
            if (elem.isJsonObject()) return elem.getAsJsonObject();
        }
        return null;
    }
}
