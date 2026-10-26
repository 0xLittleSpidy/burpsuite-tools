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

    public DiscoveredEndpoint_littlespidy() {
        this.id = UUID.randomUUID().toString();
        this.method = "GET";
        this.path = "/";
        this.summary = "";
        this.description = "";
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

    public String getParametersSummary() {
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
}
