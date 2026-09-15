// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.littlespidy.headerinspector.method.knowledge.HttpDevMethodDoc;
import com.littlespidy.headerinspector.method.knowledge.HttpDevMethodKnowledgeBase;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Groups all traffic records discovered under a specific HTTP method (e.g. GET, POST, PUT).
 * Enriches each method with official RFC safety, idempotency, and cacheability semantics from http.dev,
 * aggregates target domains, endpoints, and status codes, and provides fast multi-attribute filtering.
 *
 * @author littlespidy
 */
public class MethodGroup {

    private final String method;
    private final boolean safe;
    private final boolean idempotent;
    private final String cacheable;
    private final Map<String, MethodEndpointRecord> endpointMap = new LinkedHashMap<>();

    public MethodGroup(String method) {
        this.method = method != null ? method.toUpperCase(Locale.ROOT).trim() : "UNKNOWN";
        HttpDevMethodDoc doc = HttpDevMethodKnowledgeBase.get(this.method);
        if (doc != null) {
            this.safe = doc.safe();
            this.idempotent = doc.idempotent();
            this.cacheable = doc.cacheable();
        } else {
            this.safe = false;
            this.idempotent = false;
            this.cacheable = "Unknown";
        }
    }

    public synchronized void addEndpoint(
            AtomicInteger idGen,
            String url,
            String path,
            String domain,
            int statusCode,
            ProxyHttpRequestResponse message) {
        if (url == null || url.isBlank()) return;
        MethodEndpointRecord record = endpointMap.get(url);
        if (record == null) {
            record = new MethodEndpointRecord(idGen.getAndIncrement(), method, url, path, domain, statusCode, message);
            endpointMap.put(url, record);
        } else {
            record.recordOccurrence(statusCode, message);
        }
    }

    public String method() {
        return method;
    }

    public boolean isSafe() {
        return safe;
    }

    public String safeFormatted() {
        return safe ? "Yes" : "No";
    }

    public boolean isIdempotent() {
        return idempotent;
    }

    public String idempotentFormatted() {
        return idempotent ? "Yes" : "No";
    }

    public String cacheable() {
        return cacheable;
    }

    public synchronized int uniqueEndpointsCount() {
        return endpointMap.size();
    }

    public synchronized int totalRequests() {
        int sum = 0;
        for (MethodEndpointRecord rec : endpointMap.values()) {
            sum += rec.occurrences();
        }
        return sum;
    }

    public synchronized Set<String> allDomains() {
        Set<String> domains = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (MethodEndpointRecord rec : endpointMap.values()) {
            if (rec.domain() != null && !rec.domain().isBlank()) {
                domains.add(rec.domain());
            }
        }
        return domains;
    }

    public synchronized int uniqueDomainsCount() {
        return allDomains().size();
    }

    public synchronized List<MethodEndpointRecord> getEndpoints() {
        List<MethodEndpointRecord> list = new ArrayList<>(endpointMap.values());
        list.sort((a, b) -> Integer.compare(b.occurrences(), a.occurrences()));
        return list;
    }

    public synchronized boolean matches(
            String domainFilter,
            String searchFilter,
            String safetyFilter,
            String cacheableFilter) {

        // Safety filter
        if (safetyFilter != null && !safetyFilter.equalsIgnoreCase("All")) {
            if (safetyFilter.equalsIgnoreCase("Safe") && !safe) return false;
            if (safetyFilter.equalsIgnoreCase("Unsafe") && safe) return false;
        }

        // Cacheability filter
        if (cacheableFilter != null && !cacheableFilter.equalsIgnoreCase("All")) {
            if (cacheableFilter.equalsIgnoreCase("Cacheable") && !cacheable.toLowerCase().contains("yes") && !cacheable.toLowerCase().contains("conditional")) {
                return false;
            }
            if (cacheableFilter.equalsIgnoreCase("Non-Cacheable") && (cacheable.equalsIgnoreCase("yes") || cacheable.toLowerCase().contains("conditional"))) {
                return false;
            }
        }

        // Domain filter
        if (domainFilter != null && !domainFilter.isBlank()) {
            String df = domainFilter.trim().toLowerCase(Locale.ROOT);
            boolean matchedDomain = false;
            for (String d : allDomains()) {
                if (d.toLowerCase(Locale.ROOT).contains(df)) {
                    matchedDomain = true;
                    break;
                }
            }
            if (!matchedDomain) return false;
        }

        // Search filter (across method name, endpoints, or domains)
        if (searchFilter != null && !searchFilter.isBlank()) {
            String sf = searchFilter.trim().toLowerCase(Locale.ROOT);
            if (method.toLowerCase(Locale.ROOT).contains(sf)) return true;
            for (MethodEndpointRecord rec : endpointMap.values()) {
                if (rec.url().toLowerCase(Locale.ROOT).contains(sf) || rec.domain().toLowerCase(Locale.ROOT).contains(sf)) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }
}
