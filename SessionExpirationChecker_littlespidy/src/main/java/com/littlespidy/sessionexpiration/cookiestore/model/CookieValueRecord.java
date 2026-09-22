// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Represents a single unique value discovered for a given cookie name,
 * tracking how many times it was repeated across requests/responses, associated domains,
 * security attributes (from Set-Cookie), and a sample message for inspection.
 *
 * @author littlespidy
 */
public class CookieValueRecord {

    private final int id;
    private final String cookieName;
    private CookieSource source;
    private final String value;
    private final Set<String> domains = new LinkedHashSet<>();
    private int occurrences;
    private String attributes = "";

    private HttpRequestResponse sampleMessage;
    private String sampleUrl;
    private String sampleMethod;
    private int sampleStatusCode;

    public CookieValueRecord(
            int id,
            String cookieName,
            CookieSource source,
            String value,
            String domain,
            String attributes,
            HttpRequestResponse sampleMessage,
            String sampleUrl,
            String sampleMethod,
            int sampleStatusCode) {
        this.id = id;
        this.cookieName = cookieName;
        this.source = source;
        this.value = (value != null) ? value : "";
        if (domain != null && !domain.isBlank()) {
            this.domains.add(domain.trim().toLowerCase(Locale.ROOT));
        }
        if (attributes != null && !attributes.isBlank()) {
            this.attributes = attributes.trim();
        }
        this.occurrences = 1;
        this.sampleMessage = sampleMessage;
        this.sampleUrl = sampleUrl;
        this.sampleMethod = sampleMethod;
        this.sampleStatusCode = sampleStatusCode;
    }

    public synchronized void recordOccurrence(
            CookieSource occurrenceSource,
            String domain,
            String newAttributes,
            HttpRequestResponse message,
            String url,
            String method,
            int statusCode) {
        this.occurrences++;

        if (this.source != occurrenceSource && this.source != CookieSource.BOTH) {
            this.source = CookieSource.BOTH;
        }

        if (domain != null && !domain.isBlank()) {
            this.domains.add(domain.trim().toLowerCase(Locale.ROOT));
        }

        if ((this.attributes == null || this.attributes.isBlank()) && newAttributes != null && !newAttributes.isBlank()) {
            this.attributes = newAttributes.trim();
        }

        if (this.sampleMessage == null && message != null) {
            this.sampleMessage = message;
            this.sampleUrl = url;
            this.sampleMethod = method;
            this.sampleStatusCode = statusCode;
        }
    }

    public int id() { return id; }
    public String cookieName() { return cookieName; }
    public synchronized CookieSource source() { return source; }
    public String value() { return value; }
    public synchronized Set<String> domains() { return new LinkedHashSet<>(domains); }
    public synchronized String domainsFormatted() { return String.join(", ", domains); }
    public synchronized int occurrences() { return occurrences; }
    public synchronized String attributes() { return attributes; }
    public synchronized HttpRequestResponse sampleMessage() { return sampleMessage; }
    public synchronized String sampleUrl() { return (sampleUrl != null) ? sampleUrl : ""; }
    public synchronized String sampleMethod() { return (sampleMethod != null) ? sampleMethod : ""; }
    public synchronized int sampleStatusCode() { return sampleStatusCode; }

    public synchronized boolean hasDomain(String domain) {
        if (domain == null || domain.isBlank()) return true;
        String clean = domain.trim().toLowerCase(Locale.ROOT);
        for (String d : domains) {
            if (d.equalsIgnoreCase(clean) || d.endsWith("." + clean) || d.contains(clean)) {
                return true;
            }
        }
        return false;
    }
}
