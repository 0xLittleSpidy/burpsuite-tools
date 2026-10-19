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
    private String requestBodySample;
    private String contentType;
    private boolean requiresAuth;
    private List<String> authSchemes;

    public DiscoveredEndpoint_littlespidy() {
        this.id = UUID.randomUUID().toString();
        this.method = "GET";
        this.path = "/";
        this.summary = "";
        this.description = "";
        this.headers = new LinkedHashMap<>();
        this.queryParams = new LinkedHashMap<>();
        this.pathParams = new LinkedHashMap<>();
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

    public String getParametersSummary() {
        List<String> parts = new ArrayList<>();
        if (pathParams != null && !pathParams.isEmpty()) {
            parts.add("Path: " + pathParams.keySet());
        }
        if (queryParams != null && !queryParams.isEmpty()) {
            parts.add("Query: " + queryParams.keySet());
        }
        if (headers != null && !headers.isEmpty()) {
            parts.add("Headers: " + headers.keySet());
        }
        return parts.isEmpty() ? "None" : String.join("; ", parts);
    }
}
