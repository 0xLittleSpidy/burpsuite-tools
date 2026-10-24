// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.model;

import java.io.Serializable;

public class HttpLogEntry_littlespidy implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String time;
    private String method;
    private String url;
    private String probeName;
    private int statusCode;
    private int responseLength;
    private long durationMs;
    private String requestBase64;
    private String responseBase64;

    public HttpLogEntry_littlespidy() {}

    public HttpLogEntry_littlespidy(int id, String time, String method, String url, String probeName,
                                   int statusCode, int responseLength, long durationMs,
                                   String requestBase64, String responseBase64) {
        this.id = id;
        this.time = time;
        this.method = method;
        this.url = url;
        this.probeName = probeName;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.durationMs = durationMs;
        this.requestBase64 = requestBase64;
        this.responseBase64 = responseBase64;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getTime() { return time; }
    public void setTime(String time) { this.time = time; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getProbeName() { return probeName; }
    public void setProbeName(String probeName) { this.probeName = probeName; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public int getResponseLength() { return responseLength; }
    public void setResponseLength(int responseLength) { this.responseLength = responseLength; }

    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }

    public String getRequestBase64() { return requestBase64; }
    public void setRequestBase64(String requestBase64) { this.requestBase64 = requestBase64; }

    public String getResponseBase64() { return responseBase64; }
    public void setResponseBase64(String responseBase64) { this.responseBase64 = responseBase64; }
}
