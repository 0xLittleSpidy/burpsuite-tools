// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Model representing the outcome of a single CORS probe test.
 */
public class CorsTestResult_littlespidy {

    public enum CorsSeverity {
        HIGH("High"),
        MEDIUM("Medium"),
        LOW("Low"),
        INFO("Info"),
        SECURE("Secure");

        private final String label;

        CorsSeverity(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    private final int id;
    private final String method;
    private final String host;
    private final String path;
    private final String testedOrigin;
    private final String description;
    private final String reflectedAcao;
    private final boolean acacPresent;
    private final int statusCode;
    private final int responseLength;
    private final CorsSeverity severity;
    private HttpRequestResponse httpRequestResponse;
    private final long timestamp;
    private String classification; // "TRUE_POSITIVE", "FALSE_POSITIVE", or null/empty
    private byte[] requestBytes;
    private byte[] responseBytes;

    public CorsTestResult_littlespidy(int id, String method, String host, String path,
                                      String testedOrigin, String description, String reflectedAcao,
                                      boolean acacPresent, int statusCode, int responseLength,
                                      CorsSeverity severity, HttpRequestResponse httpRequestResponse) {
        this(id, method, host, path, testedOrigin, description, reflectedAcao, acacPresent, statusCode,
                responseLength, severity, httpRequestResponse, System.currentTimeMillis(), null, null);
    }

    public CorsTestResult_littlespidy(int id, String method, String host, String path,
                                      String testedOrigin, String description, String reflectedAcao,
                                      boolean acacPresent, int statusCode, int responseLength,
                                      CorsSeverity severity, HttpRequestResponse httpRequestResponse,
                                      long timestamp, byte[] requestBytes, byte[] responseBytes) {
        this.id = id;
        this.method = method != null ? method : "GET";
        this.host = host != null ? host : "";
        this.path = path != null ? path : "/";
        this.testedOrigin = testedOrigin != null ? testedOrigin : "";
        this.description = description != null ? description : "";
        this.reflectedAcao = reflectedAcao != null ? reflectedAcao : "";
        this.acacPresent = acacPresent;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.severity = severity != null ? severity : CorsSeverity.SECURE;
        this.httpRequestResponse = httpRequestResponse;
        this.timestamp = timestamp > 0 ? timestamp : System.currentTimeMillis();
        this.requestBytes = requestBytes;
        this.responseBytes = responseBytes;

        if (httpRequestResponse != null) {
            if (this.requestBytes == null && httpRequestResponse.request() != null) {
                this.requestBytes = httpRequestResponse.request().toByteArray().getBytes();
            }
            if (this.responseBytes == null && httpRequestResponse.hasResponse() && httpRequestResponse.response() != null) {
                this.responseBytes = httpRequestResponse.response().toByteArray().getBytes();
            }
        }
    }

    public int getId() {
        return id;
    }

    public String getMethod() {
        return method;
    }

    public String getHost() {
        return host;
    }

    public String getPath() {
        return path;
    }

    public String getTestedOrigin() {
        return testedOrigin;
    }

    public String getDescription() {
        return description;
    }

    public String getReflectedAcao() {
        return reflectedAcao;
    }

    public boolean isAcacPresent() {
        return acacPresent;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public CorsSeverity getSeverity() {
        return severity;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }

    public void setHttpRequestResponse(HttpRequestResponse reqResp) {
        this.httpRequestResponse = reqResp;
    }

    public String getClassification() {
        return classification;
    }

    public void setClassification(String classification) {
        this.classification = classification;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public byte[] getRequestBytes() {
        return requestBytes;
    }

    public void setRequestBytes(byte[] requestBytes) {
        this.requestBytes = requestBytes;
    }

    public byte[] getResponseBytes() {
        return responseBytes;
    }

    public void setResponseBytes(byte[] responseBytes) {
        this.responseBytes = responseBytes;
    }
}
