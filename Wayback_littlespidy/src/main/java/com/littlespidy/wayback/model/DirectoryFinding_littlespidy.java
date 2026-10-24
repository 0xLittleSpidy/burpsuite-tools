// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class DirectoryFinding_littlespidy {

    private int id;
    private String protocol;
    private String host;
    private String path;
    private String fullUrl;
    private int statusCode;
    private String matchedSignature;
    private int contentLength;
    private String timestamp;

    private transient HttpRequest request;
    private transient HttpResponse response;

    private String rawRequestBase64;
    private String rawResponseBase64;

    public DirectoryFinding_littlespidy() {
        this.protocol = "HTTP";
        this.host = "";
        this.path = "";
        this.fullUrl = "";
        this.matchedSignature = "";
        this.timestamp = "";
    }

    public DirectoryFinding_littlespidy(
            int id,
            String protocol,
            String host,
            String path,
            String fullUrl,
            int statusCode,
            String matchedSignature,
            int contentLength,
            String timestamp,
            HttpRequest request,
            HttpResponse response) {
        this.id = id;
        this.protocol = protocol != null ? protocol : "HTTP";
        this.host = host != null ? host : "";
        this.path = path != null ? path : "";
        this.fullUrl = fullUrl != null ? fullUrl : "";
        this.statusCode = statusCode;
        this.matchedSignature = matchedSignature != null ? matchedSignature : "";
        this.contentLength = contentLength;
        this.timestamp = timestamp != null ? timestamp : "";
        this.request = request;
        this.response = response;
    }

    public int getId() {
        return id;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getHost() {
        return host;
    }

    public String getPath() {
        return path;
    }

    public String getFullUrl() {
        return fullUrl;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getMatchedSignature() {
        return matchedSignature;
    }

    public int getContentLength() {
        return contentLength;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public void setRequest(HttpRequest request) {
        this.request = request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    public void setResponse(HttpResponse response) {
        this.response = response;
    }

    public String getRawRequestBase64() {
        return rawRequestBase64;
    }

    public void setRawRequestBase64(String rawRequestBase64) {
        this.rawRequestBase64 = rawRequestBase64;
    }

    public String getRawResponseBase64() {
        return rawResponseBase64;
    }

    public void setRawResponseBase64(String rawResponseBase64) {
        this.rawResponseBase64 = rawResponseBase64;
    }
}
