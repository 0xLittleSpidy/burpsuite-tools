// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.util.*;

/**
 * Represents an individual API endpoint discovered from an imported specification or collection.
 */
public class DiscoveredEndpoint_littlespidy {

    private String id;
    private String method;
    private String path;
    private String summary;
    private String description;
    private Map<String, String> headers;
    private Map<String, String> queryParams;
    private Map<String, String> pathParams;
    private Map<String, String> bodyParams;
    private Map<String, String> queryParamTypes;
    private Map<String, String> pathParamTypes;
    private Map<String, String> bodyParamTypes;
    private String requestBodySample;
    private String contentType;
    private boolean requiresAuth;
    private List<String> authSchemes;
    private String customRawRequest;
    private String tag;
    private List<String> tags;

    public DiscoveredEndpoint_littlespidy() {
        this.id = UUID.randomUUID().toString();
        this.method = "GET";
        this.path = "/";
        this.summary = "";
        this.description = "";
        this.tag = "Default";
        this.tags = new ArrayList<>();
        this.headers = new LinkedHashMap<>();
        this.queryParams = new LinkedHashMap<>();
        this.pathParams = new LinkedHashMap<>();
        this.bodyParams = new LinkedHashMap<>();
        this.queryParamTypes = new LinkedHashMap<>();
        this.pathParamTypes = new LinkedHashMap<>();
        this.bodyParamTypes = new LinkedHashMap<>();
        this.requestBodySample = "";
        this.contentType = "application/json";
        this.requiresAuth = false;
        this.authSchemes = new ArrayList<>();
    }

    public DiscoveredEndpoint_littlespidy(String method, String path, String summary) {
        this();
        this.method = method != null ? method.toUpperCase(Locale.ROOT) : "GET";
        this.path = path != null ? path : "/";
        this.summary = summary != null ? summary : "";
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method != null ? method.toUpperCase(Locale.ROOT) : "GET";
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path != null ? path : "/";
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary != null ? summary : "";
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description != null ? description : "";
    }

    public Map<String, String> getHeaders() {
        if (headers == null) headers = new LinkedHashMap<>();
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers != null ? headers : new LinkedHashMap<>();
    }

    public Map<String, String> getQueryParams() {
        if (queryParams == null) queryParams = new LinkedHashMap<>();
        return queryParams;
    }

    public void setQueryParams(Map<String, String> queryParams) {
        this.queryParams = queryParams != null ? queryParams : new LinkedHashMap<>();
    }

    public Map<String, String> getPathParams() {
        if (pathParams == null) pathParams = new LinkedHashMap<>();
        return pathParams;
    }

    public void setPathParams(Map<String, String> pathParams) {
        this.pathParams = pathParams != null ? pathParams : new LinkedHashMap<>();
    }

    public Map<String, String> getBodyParams() {
        if (bodyParams == null) bodyParams = new LinkedHashMap<>();
        return bodyParams;
    }

    public void setBodyParams(Map<String, String> bodyParams) {
        this.bodyParams = bodyParams != null ? bodyParams : new LinkedHashMap<>();
    }

    public Map<String, String> getQueryParamTypes() {
        if (queryParamTypes == null) queryParamTypes = new LinkedHashMap<>();
        return queryParamTypes;
    }

    public void setQueryParamTypes(Map<String, String> queryParamTypes) {
        this.queryParamTypes = queryParamTypes != null ? queryParamTypes : new LinkedHashMap<>();
    }

    public Map<String, String> getPathParamTypes() {
        if (pathParamTypes == null) pathParamTypes = new LinkedHashMap<>();
        return pathParamTypes;
    }

    public void setPathParamTypes(Map<String, String> pathParamTypes) {
        this.pathParamTypes = pathParamTypes != null ? pathParamTypes : new LinkedHashMap<>();
    }

    public Map<String, String> getBodyParamTypes() {
        if (bodyParamTypes == null) bodyParamTypes = new LinkedHashMap<>();
        return bodyParamTypes;
    }

    public void setBodyParamTypes(Map<String, String> bodyParamTypes) {
        this.bodyParamTypes = bodyParamTypes != null ? bodyParamTypes : new LinkedHashMap<>();
    }

    public String getRequestBodySample() {
        return requestBodySample;
    }

    public void setRequestBodySample(String requestBodySample) {
        this.requestBodySample = requestBodySample != null ? requestBodySample : "";
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType != null ? contentType : "application/json";
    }

    public boolean isRequiresAuth() {
        return requiresAuth;
    }

    public void setRequiresAuth(boolean requiresAuth) {
        this.requiresAuth = requiresAuth;
    }

    public List<String> getAuthSchemes() {
        if (authSchemes == null) authSchemes = new ArrayList<>();
        return authSchemes;
    }

    public void setAuthSchemes(List<String> authSchemes) {
        this.authSchemes = authSchemes != null ? authSchemes : new ArrayList<>();
    }

    public boolean hasCustomRequest() {
        return customRawRequest != null && !customRawRequest.isBlank();
    }

    public String getCustomRawRequest() {
        return customRawRequest;
    }

    public void setCustomRawRequest(String customRawRequest) {
        this.customRawRequest = (customRawRequest != null && !customRawRequest.isBlank()) ? customRawRequest : null;
    }

    public void resetCustomRequest() {
        this.customRawRequest = null;
    }

    private static final java.util.regex.Pattern PATH_VAR_REGEX = java.util.regex.Pattern.compile("\\{([a-zA-Z0-9_\\-]+)\\}|:([a-zA-Z0-9_\\-]+)");

    /**
     * Auto-discovers and populates parameters from path templates ({id}, :code),
     * query strings (?k=v), sample request bodies, and custom raw requests.
     * Ensures endpoints loaded from early sessions or specs immediately display their parameters.
     */
    public void ensureParametersDiscovered() {
        // 1. Path parameters from path template
        if (path != null) {
            String cleanPath = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
            java.util.regex.Matcher m = PATH_VAR_REGEX.matcher(cleanPath);
            while (m.find()) {
                String name = m.group(1) != null ? m.group(1) : m.group(2);
                if (name != null && !name.isBlank()) {
                    name = name.trim();
                    if (!getPathParams().containsKey(name)) {
                        getPathParams().put(name, "");
                    }
                }
            }
        }

        // 2. Query parameters from path query string (?k=v)
        if (path != null && path.contains("?")) {
            String qStr = path.substring(path.indexOf('?') + 1);
            parseAndMergeQueryString(qStr);
        }

        // 3. Body parameters from requestBodySample
        if (requestBodySample != null && !requestBodySample.isBlank()) {
            parseAndMergeBodyString(requestBodySample);
        }

        // 4. From customRawRequest if present
        if (customRawRequest != null && !customRawRequest.isBlank()) {
            String[] parts = customRawRequest.split("(\\r\\n\\r\\n|\\n\\n)", 2);
            String headerSection = parts[0];
            String bodySection = parts.length > 1 ? parts[1] : "";

            String[] lines = headerSection.split("(\\r\\n|\\n)");
            if (lines.length > 0) {
                String reqLine = lines[0].trim();
                String[] tokens = reqLine.split("\\s+");
                if (tokens.length > 1) {
                    String reqPath = tokens[1];
                    if (reqPath.contains("?")) {
                        String qStr = reqPath.substring(reqPath.indexOf('?') + 1);
                        parseAndMergeQueryString(qStr);
                    }
                    if (path != null) {
                        extractPathValuesFromLive(path, reqPath);
                    }
                }
            }

            if (!bodySection.isBlank()) {
                parseAndMergeBodyString(bodySection);
            }
        }
    }

    private void parseAndMergeQueryString(String qStr) {
        if (qStr == null || qStr.isBlank()) return;
        String[] pairs = qStr.split("&");
        for (String pair : pairs) {
            if (!pair.isBlank()) {
                int eq = pair.indexOf('=');
                String k = eq > 0 ? pair.substring(0, eq).trim() : pair.trim();
                String v = eq > 0 && eq < pair.length() - 1 ? pair.substring(eq + 1).trim() : "";
                if (!k.isBlank() && !getQueryParams().containsKey(k)) {
                    getQueryParams().put(k, v);
                }
            }
        }
    }

    private void parseAndMergeBodyString(String body) {
        if (body == null || body.isBlank()) return;
        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(trimmed);
                extractJsonKeys(el, "");
            } catch (Exception ignored) {}
        } else if (trimmed.contains("=") && !trimmed.contains("\n")) {
            String[] pairs = trimmed.split("&");
            for (String pair : pairs) {
                if (!pair.isBlank()) {
                    int eq = pair.indexOf('=');
                    String k = eq > 0 ? pair.substring(0, eq).trim() : pair.trim();
                    String v = eq > 0 && eq < pair.length() - 1 ? pair.substring(eq + 1).trim() : "";
                    if (!k.isBlank() && !getBodyParams().containsKey(k)) {
                        getBodyParams().put(k, v);
                    }
                }
            }
        }
    }

    private void extractJsonKeys(com.google.gson.JsonElement el, String prefix) {
        if (el == null || el.isJsonNull()) return;
        if (el.isJsonObject()) {
            for (Map.Entry<String, com.google.gson.JsonElement> entry : el.getAsJsonObject().entrySet()) {
                String key = entry.getKey();
                String full = prefix.isEmpty() ? key : prefix + "." + key;
                if (!getBodyParams().containsKey(full)) {
                    if (entry.getValue().isJsonPrimitive()) {
                        getBodyParams().put(full, entry.getValue().getAsString());
                    } else {
                        getBodyParams().put(full, "");
                    }
                }
                if (entry.getValue().isJsonObject()) {
                    extractJsonKeys(entry.getValue(), full);
                }
            }
        }
    }

    private void extractPathValuesFromLive(String templatePath, String livePath) {
        String cleanT = templatePath.contains("?") ? templatePath.substring(0, templatePath.indexOf('?')) : templatePath;
        String cleanL = livePath.contains("?") ? livePath.substring(0, livePath.indexOf('?')) : livePath;
        String[] tSegs = cleanT.split("/");
        String[] lSegs = cleanL.split("/");
        if (tSegs.length == lSegs.length) {
            for (int i = 0; i < tSegs.length; i++) {
                String t = tSegs[i];
                if ((t.startsWith("{") && t.endsWith("}")) || t.startsWith(":")) {
                    String paramName = t.startsWith("{") ? t.substring(1, t.length() - 1) : t.substring(1);
                    String liveVal = lSegs[i];
                    if (!liveVal.isBlank() && !liveVal.equals(t)) {
                        getPathParams().put(paramName, liveVal);
                    }
                }
            }
        }
    }

    public String getParametersSummary() {
        ensureParametersDiscovered();
        List<String> parts = new ArrayList<>();
        if (pathParams != null && !pathParams.isEmpty()) {
            parts.add("Path: " + pathParams.keySet());
        }
        if (queryParams != null && !queryParams.isEmpty()) {
            parts.add("Query: " + queryParams.keySet());
        }
        if (bodyParams != null && !bodyParams.isEmpty()) {
            parts.add("Body: " + bodyParams.keySet());
        }
        if (headers != null && !headers.isEmpty()) {
            parts.add("Headers: " + headers.keySet());
        }
        return parts.isEmpty() ? "None" : String.join("; ", parts);
    }

    public String getTag() {
        if (tag != null && !tag.isBlank()) {
            return tag;
        }
        if (tags != null && !tags.isEmpty()) {
            return tags.get(0);
        }
        return "Default";
    }

    public void setTag(String tag) {
        this.tag = (tag != null && !tag.isBlank()) ? tag : "Default";
    }

    public List<String> getTags() {
        if (tags == null) {
            tags = new ArrayList<>();
        }
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = (tags != null) ? new ArrayList<>(tags) : new ArrayList<>();
        if (!this.tags.isEmpty() && (this.tag == null || "Default".equals(this.tag))) {
            this.tag = this.tags.get(0);
        }
    }
}
