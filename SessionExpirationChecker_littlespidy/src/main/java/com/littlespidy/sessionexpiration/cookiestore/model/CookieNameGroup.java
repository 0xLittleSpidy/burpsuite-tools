// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Groups all unique values discovered under a specific cookie name.
 * Maintains unique value records, calculates aggregate repetition statistics,
 * and supports domain and text-based filtering.
 *
 * @author littlespidy
 */
public class CookieNameGroup {

    private final String displayName;
    private final String lowercaseName;
    private CookieSource source;
    private final Map<String, CookieValueRecord> valuesMap = new LinkedHashMap<>();

    public CookieNameGroup(String displayName, CookieSource source) {
        this.displayName = displayName;
        this.lowercaseName = displayName.toLowerCase(Locale.ROOT).trim();
        this.source = source;
    }

    public synchronized void addCookieValue(
            AtomicInteger idGen,
            String value,
            CookieSource valueSource,
            String domain,
            String attributes,
            HttpRequestResponse message,
            String url,
            String method,
            int statusCode) {
        if (value == null) value = "";

        if (this.source != valueSource && this.source != CookieSource.BOTH) {
            this.source = CookieSource.BOTH;
        }

        CookieValueRecord record = valuesMap.get(value);
        if (record == null) {
            record = new CookieValueRecord(
                    idGen.getAndIncrement(),
                    displayName,
                    valueSource,
                    value,
                    domain,
                    attributes,
                    message,
                    url,
                    method,
                    statusCode
            );
            valuesMap.put(value, record);
        } else {
            record.recordOccurrence(valueSource, domain, attributes, message, url, method, statusCode);
        }
    }

    public String displayName() { return displayName; }
    public String cookieName() { return displayName; }
    public String lowercaseName() { return lowercaseName; }
    public synchronized CookieSource source() { return source; }

    public synchronized int uniqueValuesCount() {
        return valuesMap.size();
    }

    public synchronized Set<String> allDomains() {
        Set<String> domains = new LinkedHashSet<>();
        for (CookieValueRecord record : valuesMap.values()) {
            domains.addAll(record.domains());
        }
        return domains;
    }

    public synchronized int domainsCount() {
        return allDomains().size();
    }

    public synchronized int totalOccurrences() {
        int sum = 0;
        for (CookieValueRecord record : valuesMap.values()) {
            sum += record.occurrences();
        }
        return sum;
    }

    public synchronized List<CookieValueRecord> getValues() {
        List<CookieValueRecord> list = new ArrayList<>(valuesMap.values());
        // Sort by occurrence count descending, then value alphabetically
        list.sort((a, b) -> {
            int cmp = Integer.compare(b.occurrences(), a.occurrences());
            if (cmp != 0) return cmp;
            return a.value().compareToIgnoreCase(b.value());
        });
        return list;
    }

    public synchronized List<CookieValueRecord> getValuesFiltered(String domainFilter, String searchFilter) {
        List<CookieValueRecord> list = new ArrayList<>();
        String domainClean = (domainFilter != null) ? domainFilter.trim().toLowerCase(Locale.ROOT) : "";
        String searchClean = (searchFilter != null) ? searchFilter.trim().toLowerCase(Locale.ROOT) : "";

        for (CookieValueRecord rec : valuesMap.values()) {
            if (!domainClean.isEmpty() && !rec.hasDomain(domainClean)) {
                continue;
            }
            if (!searchClean.isEmpty()) {
                boolean matchName = displayName.toLowerCase(Locale.ROOT).contains(searchClean);
                boolean matchVal = rec.value().toLowerCase(Locale.ROOT).contains(searchClean);
                boolean matchDom = rec.domainsFormatted().toLowerCase(Locale.ROOT).contains(searchClean);
                boolean matchAttr = rec.attributes().toLowerCase(Locale.ROOT).contains(searchClean);
                if (!matchName && !matchVal && !matchDom && !matchAttr) {
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

    public synchronized boolean matches(CookieSource sourceFilter, String domainFilter, String searchFilter) {
        if (sourceFilter != null && sourceFilter != CookieSource.BOTH) {
            if (this.source != sourceFilter && this.source != CookieSource.BOTH) {
                return false;
            }
        }
        return !getValuesFiltered(domainFilter, searchFilter).isEmpty();
    }
}
