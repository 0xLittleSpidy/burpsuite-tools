// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

/**
 * Model representing an API endpoint saved in Hidden API Storage.
 * Captures endpoints discovered during Endpoint Discovery, JS Analysis,
 * REST API Version Probing, or manually ingested from Burp tools.
 */
public class HiddenEndpoint_littlespidy {

    private String id;
    private String source;
    private String method;
    private String url;
    private String path;
    private String parametersSummary;
    private int statusCode;
    private String notes;
    private long discoveredAt;
    private HttpRequest rawRequest;
    private HttpResponse rawResponse;

    public HiddenEndpoint_littlespidy() {
        this.id = UUID.randomUUID().toString();
        this.source = "Manual Entry";
        this.method = "GET";
        this.url = "";
        this.path = "/";
        this.parametersSummary = "";
        this.statusCode = 0;
        this.notes = "";
        this.discoveredAt = System.currentTimeMillis();
    }

    public HiddenEndpoint_littlespidy(String source, String method, String url, String path, int statusCode, String notes, HttpRequest request, HttpResponse response) {
        this();
        this.source = (source != null && !source.isBlank()) ? source : "Manual Entry";
        this.method = (method != null && !method.isBlank()) ? method.toUpperCase(Locale.ROOT) : "GET";
        this.url = url != null ? url : "";
        this.path = (path != null && !path.isBlank()) ? path : "/";
        this.statusCode = statusCode;
        this.notes = notes != null ? notes : "";
        this.rawRequest = request;
        this.rawResponse = response;
        if (request != null && (this.url == null || this.url.isBlank())) {
            this.url = request.url();
        }
        if (request != null && (this.path == null || this.path.isBlank() || "/".equals(this.path))) {
            this.path = request.path();
        }
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source != null ? source : "Manual Entry";
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = (method != null && !method.isBlank()) ? method.toUpperCase(Locale.ROOT) : "GET";
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url != null ? url : "";
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path != null ? path : "/";
    }

    public String getParametersSummary() {
        return parametersSummary;
    }

    public void setParametersSummary(String parametersSummary) {
        this.parametersSummary = parametersSummary != null ? parametersSummary : "";
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes != null ? notes : "";
    }

    public long getDiscoveredAt() {
        return discoveredAt;
    }

    public void setDiscoveredAt(long discoveredAt) {
        this.discoveredAt = discoveredAt;
    }

    public String getFormattedDate() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
        return sdf.format(new Date(discoveredAt));
    }

    public HttpRequest getRawRequest() {
        return rawRequest;
    }

    public void setRawRequest(HttpRequest rawRequest) {
        this.rawRequest = rawRequest;
    }

    public HttpResponse getRawResponse() {
        return rawResponse;
    }

    public void setRawResponse(HttpResponse rawResponse) {
        this.rawResponse = rawResponse;
    }
}
