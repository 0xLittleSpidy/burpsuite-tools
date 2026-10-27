// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import com.google.gson.*;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;

import java.net.URI;
import java.util.*;

/**
 * Parser for Postman Collections v2.0 and v2.1 (JSON format).
 */
public class PostmanParser_littlespidy implements APIParser_littlespidy {

    @Override
    public boolean canParse(String content) {
        if (content == null || content.isBlank()) return false;
        try {
            String trimmed = content.trim();
            if (!trimmed.startsWith("{")) return false;
            JsonObject root = JsonParser.parseString(trimmed).getAsJsonObject();
            if (root.has("info") && root.get("info").isJsonObject()) {
                JsonObject info = root.getAsJsonObject("info");
                if (info.has("schema") && info.get("schema").getAsString().contains("postman.com")) {
                    return true;
                }
            }
            // Fallback: check if root has "item" array and "info"
            return root.has("info") && root.has("item") && root.get("item").isJsonArray();
        } catch (Exception ignored) {
        }
        return false;
    }

    @Override
    public ParseResult_littlespidy parse(String content, String sourceLocation, String sourceType) {
        try {
            JsonObject root = JsonParser.parseString(content.trim()).getAsJsonObject();
            String title = "Postman Collection";
            String schema = "v2.1";

            if (root.has("info") && root.get("info").isJsonObject()) {
                JsonObject info = root.getAsJsonObject("info");
                if (info.has("name") && !info.get("name").getAsString().isBlank()) {
                    title = info.get("name").getAsString();
                }
                if (info.has("schema")) {
                    String s = info.get("schema").getAsString();
                    if (s.contains("v2.0")) schema = "v2.0";
                }
            }

            ImportedCollection_littlespidy collection = new ImportedCollection_littlespidy(
                    title,
                    "Postman " + schema,
                    sourceType,
                    sourceLocation
            );

            List<DiscoveredEndpoint_littlespidy> endpoints = new ArrayList<>();
            String[] detectedBaseUrl = new String[1];

            if (root.has("item") && root.get("item").isJsonArray()) {
                traverseItems(root.getAsJsonArray("item"), endpoints, detectedBaseUrl, collection, "General");
            }

            if (detectedBaseUrl[0] != null && !detectedBaseUrl[0].isBlank()) {
                collection.setTargetBaseUrl(detectedBaseUrl[0]);
            }

            collection.setEndpoints(endpoints);
            collection.setImportStatus("Parsed Successfully (" + endpoints.size() + " endpoints)");
            return ParseResult_littlespidy.success(collection);

        } catch (Exception ex) {
            return ParseResult_littlespidy.failure("Postman Collection parsing error: " + ex.getMessage());
        }
    }

    private void traverseItems(JsonArray items, List<DiscoveredEndpoint_littlespidy> endpoints, String[] detectedBaseUrl, ImportedCollection_littlespidy collection, String currentFolder) {
        for (JsonElement itemElem : items) {
            if (!itemElem.isJsonObject()) continue;
            JsonObject itemObj = itemElem.getAsJsonObject();

            if (itemObj.has("item") && itemObj.get("item").isJsonArray()) {
                // Folder - recurse
                String folderName = itemObj.has("name") ? itemObj.get("name").getAsString().trim() : currentFolder;
                if (folderName.isEmpty()) folderName = currentFolder;
                if (itemObj.has("description") && !itemObj.get("description").isJsonNull()) {
                    String desc = itemObj.get("description").isJsonObject()
                            ? (itemObj.getAsJsonObject("description").has("content") ? itemObj.getAsJsonObject("description").get("content").getAsString() : "")
                            : itemObj.get("description").getAsString();
                    if (!desc.isBlank()) {
                        collection.getTagDescriptions().put(folderName, desc.trim());
                    }
                }
                traverseItems(itemObj.getAsJsonArray("item"), endpoints, detectedBaseUrl, collection, folderName);
            } else if (itemObj.has("request")) {
                // Request item
                DiscoveredEndpoint_littlespidy ep = parsePostmanRequest(itemObj, detectedBaseUrl, currentFolder);
                if (ep != null) {
                    endpoints.add(ep);
                }
            }
        }
    }

    private DiscoveredEndpoint_littlespidy parsePostmanRequest(JsonObject itemObj, String[] detectedBaseUrl, String currentFolder) {
        JsonElement reqElem = itemObj.get("request");
        String name = itemObj.has("name") ? itemObj.get("name").getAsString() : "";

        if (reqElem.isJsonPrimitive()) {
            // Simple URL string request
            String urlStr = reqElem.getAsString();
            DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", extractPath(urlStr), name);
            ep.setTag(currentFolder != null && !currentFolder.isBlank() ? currentFolder : "General");
            checkAndSetBaseUrl(urlStr, detectedBaseUrl);
            return ep;
        }

        if (!reqElem.isJsonObject()) return null;
        JsonObject req = reqElem.getAsJsonObject();

        String method = req.has("method") ? req.get("method").getAsString() : "GET";
        String path = "/";
        Map<String, String> queryParams = new LinkedHashMap<>();
        Map<String, String> headers = new LinkedHashMap<>();
        Map<String, String> pathParams = new LinkedHashMap<>();
        Map<String, String> bodyParams = new LinkedHashMap<>();
        String bodySample = "";
        String contentType = "application/json";

        // URL parsing
        if (req.has("url")) {
            JsonElement urlEl = req.get("url");
            if (urlEl.isJsonPrimitive()) {
                String fullUrl = urlEl.getAsString();
                path = extractPath(fullUrl);
                checkAndSetBaseUrl(fullUrl, detectedBaseUrl);
            } else if (urlEl.isJsonObject()) {
                JsonObject urlObj = urlEl.getAsJsonObject();
                if (urlObj.has("raw")) {
                    String raw = urlObj.get("raw").getAsString();
                    path = extractPath(raw);
                    checkAndSetBaseUrl(raw, detectedBaseUrl);
                } else if (urlObj.has("path") && urlObj.get("path").isJsonArray()) {
                    StringBuilder sb = new StringBuilder();
                    for (JsonElement p : urlObj.getAsJsonArray("path")) {
                        sb.append("/").append(p.getAsString());
                    }
                    path = sb.toString();
                }

                // Query parameters
                if (urlObj.has("query") && urlObj.get("query").isJsonArray()) {
                    for (JsonElement qEl : urlObj.getAsJsonArray("query")) {
                        if (qEl.isJsonObject()) {
                            JsonObject q = qEl.getAsJsonObject();
                            String k = q.has("key") ? q.get("key").getAsString() : "";
                            String v = q.has("value") && !q.get("value").isJsonNull() ? q.get("value").getAsString() : "sample";
                            if (!k.isBlank()) queryParams.put(k, v);
                        }
                    }
                }

                // Variables (path params)
                if (urlObj.has("variable") && urlObj.get("variable").isJsonArray()) {
                    for (JsonElement vEl : urlObj.getAsJsonArray("variable")) {
                        if (vEl.isJsonObject()) {
                            JsonObject v = vEl.getAsJsonObject();
                            String k = v.has("key") ? v.get("key").getAsString() : "";
                            String val = v.has("value") && !v.get("value").isJsonNull() ? v.get("value").getAsString() : "1";
                            if (!k.isBlank()) pathParams.put(k, val);
                        }
                    }
                }
            }
        }

        // Headers
        if (req.has("header") && req.get("header").isJsonArray()) {
            for (JsonElement hEl : req.getAsJsonArray("header")) {
                if (hEl.isJsonObject()) {
                    JsonObject h = hEl.getAsJsonObject();
                    String k = h.has("key") ? h.get("key").getAsString() : "";
                    String v = h.has("value") ? h.get("value").getAsString() : "";
                    if (!k.isBlank()) {
                        headers.put(k, v);
                        if ("content-type".equalsIgnoreCase(k)) {
                            contentType = v;
                        }
                    }
                }
            }
        }

        // Request Body
        if (req.has("body") && req.get("body").isJsonObject()) {
            JsonObject body = req.getAsJsonObject("body");
            String mode = body.has("mode") ? body.get("mode").getAsString() : "raw";
            if ("raw".equalsIgnoreCase(mode) && body.has("raw")) {
                bodySample = body.get("raw").getAsString();
                if (bodySample != null && !bodySample.isBlank()) {
                    try {
                        JsonElement parsed = JsonParser.parseString(bodySample.trim());
                        JsonSchemaResolver_littlespidy.extractParamsFromJsonElement(parsed, "", bodyParams);
                    } catch (Exception ignored) {
                    }
                }
            } else if ("urlencoded".equalsIgnoreCase(mode) && body.has("urlencoded") && body.get("urlencoded").isJsonArray()) {
                StringBuilder formBody = new StringBuilder();
                for (JsonElement el : body.getAsJsonArray("urlencoded")) {
                    if (el.isJsonObject()) {
                        JsonObject obj = el.getAsJsonObject();
                        String k = obj.has("key") ? obj.get("key").getAsString() : "";
                        String v = obj.has("value") && !obj.get("value").isJsonNull() ? obj.get("value").getAsString() : "sample";
                        if (!k.isBlank()) {
                            bodyParams.put(k, v);
                            if (formBody.length() > 0) formBody.append("&");
                            formBody.append(k).append("=").append(v);
                        }
                    }
                }
                bodySample = formBody.toString();
                if ("application/json".equals(contentType)) {
                    contentType = "application/x-www-form-urlencoded";
                }
            } else if ("formdata".equalsIgnoreCase(mode) && body.has("formdata") && body.get("formdata").isJsonArray()) {
                StringBuilder formBody = new StringBuilder();
                for (JsonElement el : body.getAsJsonArray("formdata")) {
                    if (el.isJsonObject()) {
                        JsonObject obj = el.getAsJsonObject();
                        String k = obj.has("key") ? obj.get("key").getAsString() : "";
                        String v = obj.has("value") && !obj.get("value").isJsonNull() ? obj.get("value").getAsString() : "sample";
                        if (!k.isBlank()) {
                            bodyParams.put(k, v);
                            if (formBody.length() > 0) formBody.append("&");
                            formBody.append(k).append("=").append(v);
                        }
                    }
                }
                bodySample = formBody.toString();
                if ("application/json".equals(contentType)) {
                    contentType = "multipart/form-data";
                }
            }
        }

        // Auth
        boolean hasAuth = req.has("auth") && !req.get("auth").isJsonNull();

        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy(method, path, name);
        ep.setTag(currentFolder != null && !currentFolder.isBlank() ? currentFolder : "General");
        ep.setQueryParams(queryParams);
        ep.setHeaders(headers);
        ep.setPathParams(pathParams);
        ep.setBodyParams(bodyParams);
        ep.setRequestBodySample(bodySample);
        ep.setContentType(contentType);
        ep.setRequiresAuth(hasAuth);

        return ep;
    }

    private String extractPath(String urlStr) {
        if (urlStr == null || urlStr.isBlank()) return "/";
        try {
            if (!urlStr.contains("://")) {
                int qIdx = urlStr.indexOf('?');
                return qIdx >= 0 ? urlStr.substring(0, qIdx) : urlStr;
            }
            URI uri = URI.create(urlStr);
            String path = uri.getPath();
            return (path == null || path.isBlank()) ? "/" : path;
        } catch (Exception e) {
            int qIdx = urlStr.indexOf('?');
            String withoutQ = qIdx >= 0 ? urlStr.substring(0, qIdx) : urlStr;
            int schemeIdx = withoutQ.indexOf("://");
            if (schemeIdx >= 0) {
                int firstSlash = withoutQ.indexOf('/', schemeIdx + 3);
                return firstSlash >= 0 ? withoutQ.substring(firstSlash) : "/";
            }
            return "/";
        }
    }

    private void checkAndSetBaseUrl(String urlStr, String[] holder) {
        if (holder[0] == null && urlStr != null && urlStr.contains("://")) {
            try {
                URI uri = URI.create(urlStr);
                String base = uri.getScheme() + "://" + uri.getHost();
                if (uri.getPort() > 0 && uri.getPort() != 80 && uri.getPort() != 443) {
                    base += ":" + uri.getPort();
                }
                holder[0] = base;
            } catch (Exception ignored) {
            }
        }
    }
}
