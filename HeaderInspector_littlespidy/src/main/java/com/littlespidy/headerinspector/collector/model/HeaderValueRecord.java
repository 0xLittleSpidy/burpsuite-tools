// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents a single unique value for a given header name, along with all
 * associated domains where this exact header-value pair was observed, total
 * occurrence counts, and a sample request/response for Montoya editor inspection.
 *
 * @author littlespidy
 */
public class HeaderValueRecord {

    private final int id;
    private final String headerName;
    private final HeaderType type;
    private final String value;
    private final Set<String> domains = new LinkedHashSet<>();
    private int occurrences;

    private ProxyHttpRequestResponse sampleMessage;
    private String sampleUrl;
    private String sampleMethod;
    private int sampleStatusCode;

    public HeaderValueRecord(
            int id,
            String headerName,
            HeaderType type,
            String value,
            String domain,
            ProxyHttpRequestResponse sampleMessage,
            String sampleUrl,
            String sampleMethod,
            int sampleStatusCode) {
        this.id = id;
        this.headerName = headerName;
        this.type = type;
        this.value = value;
        if (domain != null && !domain.isBlank()) {
            this.domains.add(domain.trim().toLowerCase());
        }
        this.occurrences = 1;
        this.sampleMessage = sampleMessage;
        this.sampleUrl = sampleUrl;
        this.sampleMethod = sampleMethod;
        this.sampleStatusCode = sampleStatusCode;
    }

    public synchronized void recordOccurrence(
            String domain,
            ProxyHttpRequestResponse message,
            String url,
            String method,
            int statusCode) {
        this.occurrences++;
        if (domain != null && !domain.isBlank()) {
            this.domains.add(domain.trim().toLowerCase());
        }
        // Retain latest or existing sample message
        if (this.sampleMessage == null && message != null) {
            this.sampleMessage = message;
            this.sampleUrl = url;
            this.sampleMethod = method;
            this.sampleStatusCode = statusCode;
        }
    }

    public int id() {
        return id;
    }

    public String headerName() {
        return headerName;
    }

    public HeaderType type() {
        return type;
    }

    public String value() {
        return value;
    }

    public synchronized Set<String> domains() {
        return new LinkedHashSet<>(domains);
    }

    public synchronized String domainsFormatted() {
        return String.join(", ", domains);
    }

    public synchronized int occurrences() {
        return occurrences;
    }

    public synchronized ProxyHttpRequestResponse sampleMessage() {
        return sampleMessage;
    }

    public synchronized String sampleUrl() {
        return sampleUrl != null ? sampleUrl : "";
    }

    public synchronized String sampleMethod() {
        return sampleMethod != null ? sampleMethod : "";
    }

    public synchronized int sampleStatusCode() {
        return sampleStatusCode;
    }

    public synchronized boolean hasDomain(String domain) {
        if (domain == null || domain.isBlank()) return true;
        String clean = domain.trim().toLowerCase();
        for (String d : domains) {
            if (d.equalsIgnoreCase(clean) || d.endsWith("." + clean) || d.contains(clean)) {
                return true;
            }
        }
        return false;
    }
}
