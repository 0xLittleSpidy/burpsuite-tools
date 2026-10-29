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
    private final HttpRequestResponse httpRequestResponse;
    private final long timestamp;

    public CorsTestResult_littlespidy(int id, String method, String host, String path,
                                      String testedOrigin, String description, String reflectedAcao,
                                      boolean acacPresent, int statusCode, int responseLength,
                                      CorsSeverity severity, HttpRequestResponse httpRequestResponse) {
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
        this.timestamp = System.currentTimeMillis();
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

    public long getTimestamp() {
        return timestamp;
    }
}
