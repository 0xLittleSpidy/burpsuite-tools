// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Model representing an HTTP transaction executed by GWTMap
 * (e.g. bootstrap JS fetch, permutation cache JS fetch, deferred fragment fetch,
 * or RPC method probe).
 *
 * @author littlespidy
 */
public class GwtHttpHistoryEntry {

    private final int id;
    private final String timestamp;
    private final String type;
    private final String method;
    private final String url;
    private final int statusCode;
    private final int responseLength;
    private final long durationMs;
    private final HttpRequestResponse requestResponse;

    public GwtHttpHistoryEntry(int id, String type, String method, String url,
                               int statusCode, int responseLength, long durationMs,
                               HttpRequestResponse requestResponse) {
        this.id = id;
        this.timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        this.type = type != null ? type : "Unknown";
        this.method = method != null ? method : "GET";
        this.url = url != null ? url : "";
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.durationMs = durationMs;
        this.requestResponse = requestResponse;
    }

    public int getId() {
        return id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getType() {
        return type;
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

    public int getResponseLength() {
        return responseLength;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }
}
