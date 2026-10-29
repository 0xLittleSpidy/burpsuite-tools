// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.inputvalidation;

import burp.IHttpRequestResponse;

/**
 * Encapsulates the results, signals, and HTTP interactions of an individual parameter fuzz probe.
 */
public class InputValidationTestResult_littlespidy {

    private final int id;
    private final String category;
    private final String method;
    private final String host;
    private final String path;
    private final String parameterName;
    private final String parameterType;
    private final String payloadName;
    private final String payloadValue;
    private final int baseStatusCode;
    private final int statusCode;
    private final int baseLength;
    private final int length;
    private final int sizeDiffPercent;
    private final String anomalyType;
    private final String evidence;
    private final IHttpRequestResponse fuzzedRequestResponse;
    private final IHttpRequestResponse baseRequestResponse;

    public InputValidationTestResult_littlespidy(
            int id,
            String category,
            String method,
            String host,
            String path,
            String parameterName,
            String parameterType,
            String payloadName,
            String payloadValue,
            int baseStatusCode,
            int statusCode,
            int baseLength,
            int length,
            int sizeDiffPercent,
            String anomalyType,
            String evidence,
            IHttpRequestResponse fuzzedRequestResponse,
            IHttpRequestResponse baseRequestResponse
    ) {
        this.id = id;
        this.category = category != null ? category : "General";
        this.method = method != null ? method : "";
        this.host = host != null ? host : "";
        this.path = path != null ? path : "";
        this.parameterName = parameterName != null ? parameterName : "";
        this.parameterType = parameterType != null ? parameterType : "URL";
        this.payloadName = payloadName != null ? payloadName : "";
        this.payloadValue = payloadValue != null ? payloadValue : "";
        this.baseStatusCode = baseStatusCode;
        this.statusCode = statusCode;
        this.baseLength = baseLength;
        this.length = length;
        this.sizeDiffPercent = sizeDiffPercent;
        this.anomalyType = anomalyType != null ? anomalyType : "Clean";
        this.evidence = evidence != null ? evidence : "";
        this.fuzzedRequestResponse = fuzzedRequestResponse;
        this.baseRequestResponse = baseRequestResponse;
    }

    public int getId() {
        return id;
    }

    public String getCategory() {
        return category;
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

    public String getParameterName() {
        return parameterName;
    }

    public String getParameterType() {
        return parameterType;
    }

    public String getPayloadName() {
        return payloadName;
    }

    public String getPayloadValue() {
        return payloadValue;
    }

    public int getBaseStatusCode() {
        return baseStatusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getBaseLength() {
        return baseLength;
    }

    public int getLength() {
        return length;
    }

    public int getSizeDiffPercent() {
        return sizeDiffPercent;
    }

    public String getAnomalyType() {
        return anomalyType;
    }

    public String getEvidence() {
        return evidence;
    }

    public IHttpRequestResponse getFuzzedRequestResponse() {
        return fuzzedRequestResponse;
    }

    public IHttpRequestResponse getBaseRequestResponse() {
        return baseRequestResponse;
    }
}
