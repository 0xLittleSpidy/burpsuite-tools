// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiefinder;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Represents the execution result and security analysis of an individual
 * cookie, authorization header, or custom authentication token isolation test.
 *
 * @author littlespidy
 */
public class FinderResult {

    public enum TestType {
        BASELINE,
        ANONYMOUS,
        COOKIE,
        AUTH_HEADER,
        CUSTOM_HEADER,
        GROUP_ALL_COOKIES,
        GROUP_ALL_HEADERS
    }

    private final int id;
    private final String componentName;
    private final TestType type;
    private final String rawValuePreview;
    private final int statusCode;
    private final long responseLength;
    private final long lengthDelta;
    private final String verdict;
    private final String signalDetails;
    private final long durationMs;
    private final HttpRequestResponse requestResponse;
    private final boolean isSessionToken;

    public FinderResult(int id, String componentName, TestType type, String rawValuePreview,
                        int statusCode, long responseLength, long lengthDelta,
                        String verdict, String signalDetails, long durationMs,
                        HttpRequestResponse requestResponse, boolean isSessionToken) {
        this.id = id;
        this.componentName = componentName;
        this.type = type;
        this.rawValuePreview = rawValuePreview;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.lengthDelta = lengthDelta;
        this.verdict = verdict;
        this.signalDetails = signalDetails;
        this.durationMs = durationMs;
        this.requestResponse = requestResponse;
        this.isSessionToken = isSessionToken;
    }

    public int getId() {
        return id;
    }

    public String getComponentName() {
        return componentName;
    }

    public TestType getType() {
        return type;
    }

    public String getRawValuePreview() {
        return rawValuePreview;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public long getResponseLength() {
        return responseLength;
    }

    public long getLengthDelta() {
        return lengthDelta;
    }

    public String getVerdict() {
        return verdict;
    }

    public String getSignalDetails() {
        return signalDetails;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public boolean isSessionToken() {
        return isSessionToken;
    }
}
