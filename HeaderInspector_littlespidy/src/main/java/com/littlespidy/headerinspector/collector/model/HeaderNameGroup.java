// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Groups all unique values discovered under a specific HTTP header name and direction
 * (Request or Response). Maintains unique value records, calculates aggregate statistics,
 * and enables domain-based and keyword-based filtering.
 *
 * @author littlespidy
 */
public class HeaderNameGroup {

    private final String displayName;
    private final String lowercaseName;
    private final HeaderType type;
    private final Map<String, HeaderValueRecord> valuesMap = new LinkedHashMap<>();

    public HeaderNameGroup(String displayName, HeaderType type) {
        this.displayName = displayName;
        this.lowercaseName = displayName.toLowerCase().trim();
        this.type = type;
    }

    public synchronized void addHeaderValue(
            AtomicInteger idGen,
            String value,
            String domain,
            ProxyHttpRequestResponse message,
            String url,
            String method,
            int statusCode) {
        if (value == null) value = "";
        HeaderValueRecord record = valuesMap.get(value);
        if (record == null) {
            record = new HeaderValueRecord(
                    idGen.getAndIncrement(),
                    displayName,
                    type,
                    value,
                    domain,
                    message,
                    url,
                    method,
                    statusCode
            );
            valuesMap.put(value, record);
        } else {
            record.recordOccurrence(domain, message, url, method, statusCode);
        }
    }

    public String displayName() {
        return displayName;
    }

    public String headerName() {
        return displayName;
    }

    public String lowercaseName() {
        return lowercaseName;
    }

    public HeaderType type() {
        return type;
    }

    public synchronized int uniqueValuesCount() {
        return valuesMap.size();
    }

    public synchronized Set<String> allDomains() {
        Set<String> domains = new LinkedHashSet<>();
        for (HeaderValueRecord record : valuesMap.values()) {
            domains.addAll(record.domains());
        }
        return domains;
    }

    public synchronized int domainsCount() {
        return allDomains().size();
    }

    public synchronized int totalOccurrences() {
        int sum = 0;
        for (HeaderValueRecord record : valuesMap.values()) {
            sum += record.occurrences();
        }
        return sum;
    }

    public synchronized List<HeaderValueRecord> getValues() {
        List<HeaderValueRecord> list = new ArrayList<>(valuesMap.values());
        // Sort by occurrence count descending, then value alphabetically
        list.sort((a, b) -> {
            int cmp = Integer.compare(b.occurrences(), a.occurrences());
            if (cmp != 0) return cmp;
            return a.value().compareToIgnoreCase(b.value());
        });
        return list;
    }

    public synchronized List<HeaderValueRecord> getValuesFiltered(String domainFilter, String searchFilter) {
        List<HeaderValueRecord> list = new ArrayList<>();
        String domainClean = (domainFilter != null) ? domainFilter.trim().toLowerCase() : "";
        String searchClean = (searchFilter != null) ? searchFilter.trim().toLowerCase() : "";

        for (HeaderValueRecord rec : valuesMap.values()) {
            if (!domainClean.isEmpty() && !rec.hasDomain(domainClean)) {
                continue;
            }
            if (!searchClean.isEmpty()) {
                boolean matchName = displayName.toLowerCase().contains(searchClean);
                boolean matchVal = rec.value().toLowerCase().contains(searchClean);
                boolean matchDom = rec.domainsFormatted().toLowerCase().contains(searchClean);
                if (!matchName && !matchVal && !matchDom) {
                    continue;
                }
            }
            list.add(rec);
        }

        list.sort((a, b) -> {
            int cmp = Integer.compare(b.occurrences(), a.occurrences());
            if (cmp != 0) return cmp;
            return a.value().compareToIgnoreCase(b.value());
        });
        return list;
    }

    public synchronized boolean matches(String domainFilter, String searchFilter) {
        return !getValuesFiltered(domainFilter, searchFilter).isEmpty();
    }
}
