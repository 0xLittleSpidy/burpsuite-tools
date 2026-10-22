// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import com.google.gson.*;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import org.yaml.snakeyaml.Yaml;

import java.util.*;

/**
 * Parser for Swagger 2.0 specifications in JSON or YAML format.
 */
public class SwaggerParser_littlespidy implements APIParser_littlespidy {

    private final Gson gson = new Gson();

    @Override
    public boolean canParse(String content) {
        if (content == null || content.isBlank()) return false;
        try {
            JsonObject root = parseRootObject(content);
            if (root != null && root.has("swagger")) {
                String swagger = root.get("swagger").getAsString();
                return swagger != null && swagger.startsWith("2.");
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    @Override
    public ParseResult_littlespidy parse(String content, String sourceLocation, String sourceType) {
        try {
            JsonObject root = parseRootObject(content);
            if (root == null || !root.has("swagger")) {
                return ParseResult_littlespidy.failure("Invalid Swagger specification: missing 'swagger' version attribute.");
            }

            String title = "Swagger 2.0 Collection";
            if (root.has("info") && root.get("info").isJsonObject()) {
                JsonObject info = root.getAsJsonObject("info");
                if (info.has("title") && !info.get("title").getAsString().isBlank()) {
                    title = info.get("title").getAsString();
                }
            }

            ImportedCollection_littlespidy collection = new ImportedCollection_littlespidy(
                    title,
                    "Swagger 2.0",
                    sourceType,
                    sourceLocation
            );

            // Compute target Base URL from scheme + host + basePath
            String scheme = "https";
            if (root.has("schemes") && root.get("schemes").isJsonArray()) {
                JsonArray schemes = root.getAsJsonArray("schemes");
                if (!schemes.isEmpty()) {
                    scheme = schemes.get(0).getAsString();
                }
            }
            String host = root.has("host") ? root.get("host").getAsString() : "";
            String basePath = root.has("basePath") ? root.get("basePath").getAsString() : "";
            if (!host.isBlank()) {
                String targetBaseUrl = scheme + "://" + host;
                if (!basePath.isBlank() && !"/".equals(basePath)) {
                    if (!basePath.startsWith("/")) targetBaseUrl += "/";
                    targetBaseUrl += basePath;
                }
                collection.setTargetBaseUrl(targetBaseUrl);
            }

            // Extract Endpoints
            List<DiscoveredEndpoint_littlespidy> endpoints = new ArrayList<>();
            if (root.has("paths") && root.get("paths").isJsonObject()) {
                JsonObject pathsObj = root.getAsJsonObject("paths");
                for (Map.Entry<String, JsonElement> pathEntry : pathsObj.entrySet()) {
                    String path = pathEntry.getKey();
                    if (!pathEntry.getValue().isJsonObject()) continue;
                    JsonObject pathItem = pathEntry.getValue().getAsJsonObject();

                    Map<String, String> commonPathParams = new LinkedHashMap<>();
                    Map<String, String> commonQueryParams = new LinkedHashMap<>();
                    Map<String, String> commonHeaders = new LinkedHashMap<>();
                    Map<String, String> commonBodyParams = new LinkedHashMap<>();
                    Map<String, String> commonPathTypes = new LinkedHashMap<>();
                    Map<String, String> commonQueryTypes = new LinkedHashMap<>();
                    Map<String, String> commonBodyTypes = new LinkedHashMap<>();
                    if (pathItem.has("parameters") && pathItem.get("parameters").isJsonArray()) {
                        extractSwaggerParameters(root, pathItem.getAsJsonArray("parameters"), commonPathParams, commonQueryParams, commonHeaders, commonBodyParams, commonPathTypes, commonQueryTypes, commonBodyTypes, null);
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
                            Map<String, String> bodyParams = new LinkedHashMap<>(commonBodyParams);
                            Map<String, String> pathTypes = new LinkedHashMap<>(commonPathTypes);
                            Map<String, String> queryTypes = new LinkedHashMap<>(commonQueryTypes);
                            Map<String, String> bodyTypes = new LinkedHashMap<>(commonBodyTypes);
                            String[] bodySampleHolder = new String[1];

                            if (op.has("parameters") && op.get("parameters").isJsonArray()) {
                                extractSwaggerParameters(root, op.getAsJsonArray("parameters"), pathParams, queryParams, headers, bodyParams, pathTypes, queryTypes, bodyTypes, bodySampleHolder);
                            }
                            ep.setPathParams(pathParams);
                            ep.setQueryParams(queryParams);
                            ep.setHeaders(headers);
                            ep.setBodyParams(bodyParams);
                            ep.setPathParamTypes(pathTypes);
                            ep.setQueryParamTypes(queryTypes);
                            ep.setBodyParamTypes(bodyTypes);
                            if (bodySampleHolder[0] != null && !bodySampleHolder[0].isBlank()) {
                                ep.setRequestBodySample(bodySampleHolder[0]);
                            } else if (!bodyParams.isEmpty() && ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method))) {
                                StringBuilder formBody = new StringBuilder();
                                for (Map.Entry<String, String> bEntry : bodyParams.entrySet()) {
                                    if (formBody.length() > 0) formBody.append("&");
                                    formBody.append(bEntry.getKey()).append("=").append(bEntry.getValue());
                                }
                                ep.setRequestBodySample(formBody.toString());
                            }

                            // Consumes / Content-Type
                            if (op.has("consumes") && op.get("consumes").isJsonArray()) {
                                JsonArray consumes = op.getAsJsonArray("consumes");
                                if (!consumes.isEmpty()) {
                                    ep.setContentType(consumes.get(0).getAsString());
                                }
                            } else if (root.has("consumes") && root.get("consumes").isJsonArray()) {
                                JsonArray consumes = root.getAsJsonArray("consumes");
                                if (!consumes.isEmpty()) {
                                    ep.setContentType(consumes.get(0).getAsString());
                                }
                            }

                            // Security
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
            return ParseResult_littlespidy.failure("Swagger 2.0 parsing error: " + ex.getMessage());
        }
    }

    private void extractSwaggerParameters(
            JsonObject root,
            JsonArray paramArray,
            Map<String, String> pathParams,
            Map<String, String> queryParams,
            Map<String, String> headers,
            Map<String, String> bodyParams,
            Map<String, String> pathTypes,
            Map<String, String> queryTypes,
            Map<String, String> bodyTypes,
            String[] bodySampleHolder) {

        for (JsonElement p : paramArray) {
            if (!p.isJsonObject()) continue;
            JsonObject pObj = p.getAsJsonObject();
            String name = pObj.has("name") ? pObj.get("name").getAsString() : "";
            String in = pObj.has("in") ? pObj.get("in").getAsString().toLowerCase(Locale.ROOT) : "";
            String example = "1";
            String type = "string";

            if (pObj.has("type") && pObj.get("type").isJsonPrimitive()) {
                type = pObj.get("type").getAsString().toLowerCase(Locale.ROOT);
            } else if (pObj.has("schema") && pObj.get("schema").isJsonObject()) {
                JsonObject s = pObj.getAsJsonObject("schema");
                if (s.has("type") && s.get("type").isJsonPrimitive()) {
                    type = s.get("type").getAsString().toLowerCase(Locale.ROOT);
                }
            }

            if (pObj.has("default")) {
                example = pObj.get("default").getAsString();
            } else if ("string".equalsIgnoreCase(type)) {
                example = "sample";
            }

            if ("path".equals(in)) {
                pathParams.put(name, example);
                pathTypes.put(name, type);
            } else if ("query".equals(in)) {
                queryParams.put(name, example);
                queryTypes.put(name, type);
            } else if ("header".equals(in)) {
                headers.put(name, example);
            } else if ("body".equals(in)) {
                if (pObj.has("schema") && pObj.get("schema").isJsonObject()) {
                    JsonObject schema = pObj.getAsJsonObject("schema");
                    JsonElement sample = JsonSchemaResolver_littlespidy.generateSample(root, schema, bodyParams, new HashSet<>(), 0);
                    if (bodySampleHolder != null) {
                        bodySampleHolder[0] = gson.toJson(sample);
                    }
                }
            } else if ("formdata".equalsIgnoreCase(in)) {
                if (bodyParams != null && !name.isBlank()) {
                    bodyParams.put(name, example);
                    bodyTypes.put(name, type);
                }
            }
        }
    }

    private String generateSampleFromSwaggerSchema(JsonObject schema) {
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
