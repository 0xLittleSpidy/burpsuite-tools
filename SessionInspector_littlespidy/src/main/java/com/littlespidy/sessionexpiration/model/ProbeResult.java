// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.time.Instant;

/**
 * Encapsulates the result of a single probe request executed at a scheduled milestone.
 *
 * @author littlespidy
 */
public class ProbeResult {

    private final Instant timestamp;
    private final HttpRequestResponse requestResponse;
    private final int statusCode;
    private final long responseLength;
    private final boolean expired;
    private final String signal;
    private final long durationMillis;
    private final String errorDetails;
    private final String serverDate;

    public ProbeResult(Instant timestamp, HttpRequestResponse requestResponse, int statusCode,
                       long responseLength, boolean expired, String signal, long durationMillis,
                       String errorDetails, String serverDate) {
        this.timestamp = timestamp;
        this.requestResponse = requestResponse;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.expired = expired;
        this.signal = signal;
        this.durationMillis = durationMillis;
        this.errorDetails = errorDetails;
        this.serverDate = serverDate;
    }

    public static ProbeResult success(Instant timestamp, HttpRequestResponse requestResponse,
                                      boolean expired, String signal, long durationMillis) {
        int code = (requestResponse != null && requestResponse.hasResponse())
                ? requestResponse.response().statusCode()
                : 0;
        long len = (requestResponse != null && requestResponse.hasResponse())
                ? requestResponse.response().toByteArray().length()
                : 0;
        String sDate = (requestResponse != null && requestResponse.hasResponse())
                ? requestResponse.response().headerValue("Date")
                : null;
        return new ProbeResult(timestamp, requestResponse, code, len, expired, signal, durationMillis, null, sDate);
    }

    public static ProbeResult failure(Instant timestamp, String errorMessage, long durationMillis) {
        return new ProbeResult(timestamp, null, 0, 0, false, "Connection Error", durationMillis, errorMessage, null);
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public long getResponseLength() {
        return responseLength;
    }

    public boolean isExpired() {
        return expired;
    }

    public String getSignal() {
        return signal;
    }

    public long getDurationMillis() {
        return durationMillis;
    }

    public String getErrorDetails() {
        return errorDetails;
    }

    public String getServerDate() {
        return serverDate;
    }
}
