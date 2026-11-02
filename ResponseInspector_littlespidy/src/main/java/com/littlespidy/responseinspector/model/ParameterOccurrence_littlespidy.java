// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.LocalDateTime;

/**
 * Represents a single discovery instance of a parameter within an HTTP request/response.
 */
public class ParameterOccurrence_littlespidy {

    private final HttpRequestResponse httpRequestResponse;
    private final ParameterSource_littlespidy source;
    private final String format;
    private final String value;
    private final String url;
    private final short statusCode;
    private final String method;
    private final LocalDateTime timestamp;

    public ParameterOccurrence_littlespidy(
            HttpRequestResponse httpRequestResponse,
            ParameterSource_littlespidy source,
            String format,
            String value,
            String url,
            short statusCode,
            String method,
            LocalDateTime timestamp
    ) {
        this.httpRequestResponse = httpRequestResponse;
        this.source = source;
        this.format = format;
        this.value = value;
        this.url = url;
        this.statusCode = statusCode;
        this.method = method;
        this.timestamp = timestamp;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }

    public ParameterSource_littlespidy getSource() {
        return source;
    }

    public String getFormat() {
        return format;
    }

    public String getValue() {
        return value;
    }

    public String getUrl() {
        return url;
    }

    public short getStatusCode() {
        return statusCode;
    }

    public String getMethod() {
        return method;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}
