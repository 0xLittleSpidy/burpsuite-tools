// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Result of an individual input validation fuzzing probe.
 */
public class InputValidationTestResult_littlespidy {

    public enum ValidationSeverity {
        HIGH("High"),
        MEDIUM("Medium"),
        LOW("Low"),
        INFO("Info");

        private final String label;

        ValidationSeverity(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    private final int id;
    private final String method;
    private final String targetUrl;
    private final String parameterName;
    private final String category;
    private final String payload;
    private final int statusCode;
    private final int responseLength;
    private final String detectionIndicator;
    private final ValidationSeverity severity;
    private final HttpRequestResponse httpRequestResponse;
    private final long timestamp;

    public InputValidationTestResult_littlespidy(
            int id, String method, String targetUrl, String parameterName,
            String category, String payload, int statusCode, int responseLength,
            String detectionIndicator, ValidationSeverity severity,
            HttpRequestResponse httpRequestResponse) {
        this.id = id;
        this.method = method != null ? method : "GET";
        this.targetUrl = targetUrl != null ? targetUrl : "";
        this.parameterName = parameterName != null ? parameterName : "";
        this.category = category != null ? category : "";
        this.payload = payload != null ? payload : "";
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.detectionIndicator = detectionIndicator != null ? detectionIndicator : "";
        this.severity = severity != null ? severity : ValidationSeverity.INFO;
        this.httpRequestResponse = httpRequestResponse;
        this.timestamp = System.currentTimeMillis();
    }

    public int getId() {
        return id;
    }

    public String getMethod() {
        return method;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public String getParameterName() {
        return parameterName;
    }

    public String getCategory() {
        return category;
    }

    public String getPayload() {
        return payload;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public String getDetectionIndicator() {
        return detectionIndicator;
    }

    public ValidationSeverity getSeverity() {
        return severity;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }

    public long getTimestamp() {
        return timestamp;
    }
}
