package com.littlespidy.parampayloadinjector.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Model capturing details of a detected reflection of an injected payload in an HTTP response.
 */
public class ReflectionFinding {
    private final long id;
    private final String timestamp;
    private final String method;
    private final String url;
    private final int statusCode;
    private final String parameterName;
    private final String payloadCategory;
    private final String injectedPayload;
    private final String reflectionContext;
    private final String evidenceSnippet;
    private final HttpRequestResponse requestResponse;

    public ReflectionFinding(
            long id,
            String timestamp,
            String method,
            String url,
            int statusCode,
            String parameterName,
            String payloadCategory,
            String injectedPayload,
            String reflectionContext,
            String evidenceSnippet,
            HttpRequestResponse requestResponse) {
        this.id = id;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.parameterName = parameterName;
        this.payloadCategory = payloadCategory;
        this.injectedPayload = injectedPayload;
        this.reflectionContext = reflectionContext;
        this.evidenceSnippet = evidenceSnippet;
        this.requestResponse = requestResponse;
    }

    public long getId() {
        return id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getParameterName() {
        return parameterName;
    }

    public String getPayloadCategory() {
        return payloadCategory;
    }

    public String getInjectedPayload() {
        return injectedPayload;
    }

    public String getReflectionContext() {
        return reflectionContext;
    }

    public String getEvidenceSnippet() {
        return evidenceSnippet;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }
}
