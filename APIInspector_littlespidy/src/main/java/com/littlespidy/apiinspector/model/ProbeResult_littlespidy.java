// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Encapsulates the execution result of an API version probe.
 */
public class ProbeResult_littlespidy {
    private final int id;
    private final String strategyName;
    private final String variation;
    private final int statusCode;
    private final int responseLength;
    private final String mimeType;
    private final String diffAnalysis;
    private final long latencyMs;
    private final HttpRequest request;
    private final HttpResponse response;

    public ProbeResult_littlespidy(
            int id,
            String strategyName,
            String variation,
            int statusCode,
            int responseLength,
            String mimeType,
            String diffAnalysis,
            long latencyMs,
            HttpRequest request,
            HttpResponse response) {
        this.id = id;
        this.strategyName = strategyName;
        this.variation = variation;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.mimeType = mimeType;
        this.diffAnalysis = diffAnalysis;
        this.latencyMs = latencyMs;
        this.request = request;
        this.response = response;
    }

    public int getId() {
        return id;
    }

    public String getStrategyName() {
        return strategyName;
    }

    public String getVariation() {
        return variation;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public String getMimeType() {
        return mimeType;
    }

    public String getDiffAnalysis() {
        return diffAnalysis;
    }

    public long getLatencyMs() {
        return latencyMs;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }
}
