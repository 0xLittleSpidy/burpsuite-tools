// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.littlespidy.headerinspector.status.knowledge.HttpDevStatusDoc;
import com.littlespidy.headerinspector.status.knowledge.HttpDevStatusKnowledgeBase;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Groups all traffic records returning a specific HTTP status code (e.g. 200, 302, 404, 500).
 * Enriches each status with official IANA/http.dev semantics, class definitions, and meanings,
 * aggregates target domains, endpoints, and request methods, and provides fast multi-attribute filtering.
 *
 * @author littlespidy
 */
public class StatusGroup {

    private final int statusCode;
    private final String reasonPhrase;
    private final String statusClass;
    private final String meaning;
    private final Map<String, StatusEndpointRecord> endpointMap = new LinkedHashMap<>();

    public StatusGroup(int statusCode) {
        this.statusCode = statusCode;
        HttpDevStatusDoc doc = HttpDevStatusKnowledgeBase.get(statusCode);
        if (doc != null) {
            this.reasonPhrase = doc.name();
            this.statusClass = doc.statusClass();
            this.meaning = doc.meaning();
        } else {
            this.reasonPhrase = "Status " + statusCode;
            this.statusClass = HttpDevStatusKnowledgeBase.getStatusClass(statusCode);
            this.meaning = "HTTP Response Status Code";
        }
    }

    public synchronized void addEndpoint(
            AtomicInteger idGen,
            String method,
            String url,
            String path,
            String domain,
            ProxyHttpRequestResponse message) {
        if (url == null || url.isBlank()) return;
        String key = method + " " + url;
        StatusEndpointRecord record = endpointMap.get(key);
        if (record == null) {
            record = new StatusEndpointRecord(idGen.getAndIncrement(), statusCode, method, url, path, domain, message);
            endpointMap.put(key, record);
        } else {
            record.recordOccurrence(message);
        }
    }

    public int statusCode() {
        return statusCode;
    }

    public String reasonPhrase() {
        return reasonPhrase;
    }

    public String statusClass() {
        return statusClass;
    }

    public String meaning() {
        return meaning;
    }

    public synchronized int uniqueEndpointsCount() {
        return endpointMap.size();
    }

    public synchronized int totalResponses() {
        int sum = 0;
        for (StatusEndpointRecord rec : endpointMap.values()) {
            sum += rec.occurrences();
        }
        return sum;
    }

    public synchronized Set<String> allDomains() {
        Set<String> domains = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (StatusEndpointRecord rec : endpointMap.values()) {
            if (rec.domain() != null && !rec.domain().isBlank()) {
                domains.add(rec.domain());
            }
        }
        return domains;
    }

    public synchronized int uniqueDomainsCount() {
        return allDomains().size();
    }

    public synchronized List<StatusEndpointRecord> getEndpoints() {
        List<StatusEndpointRecord> list = new ArrayList<>(endpointMap.values());
        list.sort((a, b) -> Integer.compare(b.occurrences(), a.occurrences()));
        return list;
    }

    public synchronized boolean matches(
            String domainFilter,
            String searchFilter,
            String classFilter) {

        // Class filter (e.g. 1xx, 2xx, 3xx, 4xx, 5xx, Vendor/Extended)
        if (classFilter != null && !classFilter.equalsIgnoreCase("All Status Codes") && !classFilter.equalsIgnoreCase("All")) {
            String cf = classFilter.toLowerCase(Locale.ROOT);
            if (cf.startsWith("1xx") && (statusCode < 100 || statusCode > 199)) return false;
            if (cf.startsWith("2xx") && (statusCode < 200 || statusCode > 299)) return false;
            if (cf.startsWith("3xx") && (statusCode < 300 || statusCode > 399)) return false;
            if (cf.startsWith("4xx") && (statusCode < 400 || statusCode > 499)) return false;
            if (cf.startsWith("5xx") && (statusCode < 500 || statusCode > 599)) return false;
            if (cf.contains("vendor") || cf.contains("extended")) {
                boolean isVendor = (inRangeVendor() || statusClass.toLowerCase(Locale.ROOT).contains("vendor"));
                if (!isVendor) return false;
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

        // Search filter (code, reason phrase, URL, or domain)
        if (searchFilter != null && !searchFilter.isBlank()) {
            String sf = searchFilter.trim().toLowerCase(Locale.ROOT);
            if (String.valueOf(statusCode).contains(sf)) return true;
            if (reasonPhrase.toLowerCase(Locale.ROOT).contains(sf)) return true;
            if (statusClass.toLowerCase(Locale.ROOT).contains(sf)) return true;
            for (StatusEndpointRecord rec : endpointMap.values()) {
                if (rec.url().toLowerCase(Locale.ROOT).contains(sf) ||
                    rec.domain().toLowerCase(Locale.ROOT).contains(sf) ||
                    rec.method().toLowerCase(Locale.ROOT).contains(sf)) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }

    private boolean inRangeVendor() {
        return statusCode >= 600 ||
               (statusCode >= 520 && statusCode <= 562) ||
               statusCode == 444 || statusCode == 499 || statusCode == 440 ||
               statusCode == 449 || statusCode == 450 || statusCode == 460 ||
               statusCode == 463 || statusCode == 464 || statusCode == 470 ||
               (statusCode >= 492 && statusCode <= 498);
    }
}
