// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents an individual endpoint/URL and HTTP method returning a specific status code.
 * Tracks occurrence frequency, target domain, and maintains a reference to a sample
 * Proxy request/response pair for master-detail inspection.
 *
 * @author littlespidy
 */
public class StatusEndpointRecord {

    private final int id;
    private final int statusCode;
    private final String method;
    private final String url;
    private final String path;
    private final String domain;
    private int occurrences = 0;
    private ProxyHttpRequestResponse sampleMessage;

    public StatusEndpointRecord(
            int id,
            int statusCode,
            String method,
            String url,
            String path,
            String domain,
            ProxyHttpRequestResponse sampleMessage) {
        this.id = id;
        this.statusCode = statusCode;
        this.method = method;
        this.url = url;
        this.path = path;
        this.domain = domain;
        this.occurrences = 1;
        this.sampleMessage = sampleMessage;
    }

    public synchronized void recordOccurrence(ProxyHttpRequestResponse message) {
        this.occurrences++;
        if (message != null && (this.sampleMessage == null || (!this.sampleMessage.hasResponse() && message.hasResponse()))) {
            this.sampleMessage = message;
        }
    }

    public int id() {
        return id;
    }

    public int statusCode() {
        return statusCode;
    }

    public String method() {
        return method;
    }

    public String url() {
        return url;
    }

    public String path() {
        return path;
    }

    public String domain() {
        return domain;
    }

    public synchronized int occurrences() {
        return occurrences;
    }

    public synchronized ProxyHttpRequestResponse sampleMessage() {
        return sampleMessage;
    }
}
