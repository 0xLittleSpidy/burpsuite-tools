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
    private HttpRequestResponse httpRequestResponse;
    private final long timestamp;
    private String classification; // "TRUE_POSITIVE", "FALSE_POSITIVE", or null/empty
    private byte[] requestBytes;
    private byte[] responseBytes;

    public InputValidationTestResult_littlespidy(
            int id, String method, String targetUrl, String parameterName,
            String category, String payload, int statusCode, int responseLength,
            String detectionIndicator, ValidationSeverity severity,
            HttpRequestResponse httpRequestResponse) {
        this(id, method, targetUrl, parameterName, category, payload, statusCode,
                responseLength, detectionIndicator, severity, httpRequestResponse,
                System.currentTimeMillis(), null, null);
    }

    public InputValidationTestResult_littlespidy(
            int id, String method, String targetUrl, String parameterName,
            String category, String payload, int statusCode, int responseLength,
            String detectionIndicator, ValidationSeverity severity,
            HttpRequestResponse httpRequestResponse,
            long timestamp, byte[] requestBytes, byte[] responseBytes) {
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
