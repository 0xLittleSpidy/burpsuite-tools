// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * Model representing an HTTP request/response captured from Burp Suite's HTTP Proxy history.
 * Contains extracted GWT RPC metadata (Method Name, Service, GWT-RPC status).
 *
 * @author littlespidy
 */
public class GwtProxyHistoryEntry {

    private final int id;
    private final String timestamp;
    private final String httpMethod;
    private final String methodName;
    private final String service;
    private final String url;
    private final int statusCode;
    private final int responseLength;
    private final String mimeType;
    private final long durationMs;
    private final boolean isGwtRpc;
    private final ProxyHttpRequestResponse proxyItem;

    public GwtProxyHistoryEntry(int id, String timestamp, String httpMethod, String methodName,
                                String service, String url, int statusCode, int responseLength,
                                String mimeType, long durationMs, boolean isGwtRpc,
                                ProxyHttpRequestResponse proxyItem) {
        this.id = id;
        this.timestamp = timestamp != null ? timestamp : new SimpleDateFormat("HH:mm:ss").format(new Date());
        this.httpMethod = httpMethod != null ? httpMethod : "GET";
        this.methodName = methodName != null ? methodName : "";
        this.service = service != null ? service : "";
        this.url = url != null ? url : "";
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.mimeType = mimeType != null ? mimeType : "";
        this.durationMs = durationMs;
        this.isGwtRpc = isGwtRpc;
        this.proxyItem = proxyItem;
    }

    public int getId() {
        return id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getService() {
        return service;
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

    public String getMimeType() {
        return mimeType;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public boolean isGwtRpc() {
        return isGwtRpc;
    }

    public ProxyHttpRequestResponse getProxyItem() {
        return proxyItem;
    }
}
