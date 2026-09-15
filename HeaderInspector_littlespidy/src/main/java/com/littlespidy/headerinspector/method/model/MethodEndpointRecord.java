// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents an individual endpoint/URL invoked with a specific HTTP method.
 * Tracks occurrence frequency, target domain, associated HTTP status codes,
 * and maintains a reference to a sample Proxy request/response pair for master-detail inspection.
 *
 * @author littlespidy
 */
public class MethodEndpointRecord {

    private final int id;
    private final String method;
    private final String url;
    private final String path;
    private final String domain;
    private final Set<Integer> statusCodes = new TreeSet<>();
    private int occurrences = 0;
    private ProxyHttpRequestResponse sampleMessage;

    public MethodEndpointRecord(
            int id,
            String method,
            String url,
            String path,
            String domain,
            int statusCode,
            ProxyHttpRequestResponse sampleMessage) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.path = path;
        this.domain = domain;
        this.occurrences = 1;
        if (statusCode > 0) {
            this.statusCodes.add(statusCode);
        }
        this.sampleMessage = sampleMessage;
    }

    public synchronized void recordOccurrence(int statusCode, ProxyHttpRequestResponse message) {
        this.occurrences++;
        if (statusCode > 0) {
            this.statusCodes.add(statusCode);
        }
        if (message != null && (this.sampleMessage == null || (!this.sampleMessage.hasResponse() && message.hasResponse()))) {
            this.sampleMessage = message;
        }
    }

    public int id() {
        return id;
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

    public synchronized Set<Integer> statusCodes() {
        return Collections.unmodifiableSet(new TreeSet<>(statusCodes));
    }

    public synchronized String statusCodesFormatted() {
        if (statusCodes.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder();
        for (int code : statusCodes) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(code);
        }
        return sb.toString();
    }

    public synchronized ProxyHttpRequestResponse sampleMessage() {
        return sampleMessage;
    }
}
