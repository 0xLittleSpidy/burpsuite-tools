// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Model representing a logged event, intercepted request, or expiration detection.
 *
 * @author littlespidy
 */
public class ScanActivityEntry {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final long id;
    private final String timestamp;
    private final String tool;
    private final String method;
    private final String host;
    private final String url;
    private final int statusCode;
    private final String eventType;
    private final String details;
    private final HttpRequestResponse requestResponse;

    public ScanActivityEntry(long id, String tool, String method, String host, String url,
                             int statusCode, String eventType, String details,
                             HttpRequestResponse requestResponse) {
        this.id = id;
        this.timestamp = LocalDateTime.now().format(TIME_FMT);
        this.tool = tool;
        this.method = method;
        this.host = host;
        this.url = url;
        this.statusCode = statusCode;
        this.eventType = eventType;
        this.details = details;
        this.requestResponse = requestResponse;
    }

    public long getId() { return id; }
    public String getTimestamp() { return timestamp; }
    public String getTool() { return tool; }
    public String getMethod() { return method; }
    public String getHost() { return host; }
    public String getUrl() { return url; }
    public int getStatusCode() { return statusCode; }
    public String getEventType() { return eventType; }
    public String getDetails() { return details; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
}
