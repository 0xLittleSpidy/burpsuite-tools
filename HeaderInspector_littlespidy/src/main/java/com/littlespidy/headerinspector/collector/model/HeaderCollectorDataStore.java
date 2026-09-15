// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.model;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe central data store for collected HTTP request and response headers.
 * Groups multiple unique values under their respective header names, tracks associated
 * domains, and provides rich multi-faceted filtering.
 *
 * @author littlespidy
 */
public class HeaderCollectorDataStore {

    private final Map<String, HeaderNameGroup> requestHeaders = new LinkedHashMap<>();
    private final Map<String, HeaderNameGroup> responseHeaders = new LinkedHashMap<>();
    private final AtomicInteger idGen = new AtomicInteger(1);
    private int totalMessagesProcessed = 0;

    public synchronized void ingest(ProxyHttpRequestResponse item) {
        if (item == null || item.request() == null) return;
        totalMessagesProcessed++;

        String domain = "";
        if (item.request().httpService() != null && item.request().httpService().host() != null) {
            domain = item.request().httpService().host();
        }
        String url = item.request().url() != null ? item.request().url() : "";
        String method = item.request().method() != null ? item.request().method().toUpperCase() : "GET";
        int statusCode = item.hasResponse() ? item.response().statusCode() : 0;

        // Ingest Request Headers
        if (item.request().headers() != null) {
            for (HttpHeader h : item.request().headers()) {
                if (h == null || h.name() == null || h.name().isBlank()) continue;
                String name = h.name().trim();
                // Skip HTTP request-line if present
                if (name.toUpperCase().startsWith("GET ") || name.toUpperCase().startsWith("POST ") ||
                    name.toUpperCase().startsWith("PUT ") || name.toUpperCase().startsWith("DELETE ") ||
                    name.toUpperCase().startsWith("HEAD ") || name.toUpperCase().startsWith("OPTIONS ") ||
                    name.toUpperCase().startsWith("PATCH ")) {
                    continue;
                }

                String lower = name.toLowerCase();
                HeaderNameGroup group = requestHeaders.computeIfAbsent(
                        lower,
                        k -> new HeaderNameGroup(name, HeaderType.REQUEST)
                );
                group.addHeaderValue(idGen, h.value(), domain, item, url, method, statusCode);
            }
        }

        // Ingest Response Headers
        if (item.hasResponse() && item.response() != null && item.response().headers() != null) {
            for (HttpHeader h : item.response().headers()) {
                if (h == null || h.name() == null || h.name().isBlank()) continue;
                String name = h.name().trim();
                // Skip HTTP status line if present
                if (name.toUpperCase().startsWith("HTTP/")) {
                    continue;
                }

                String lower = name.toLowerCase();
                HeaderNameGroup group = responseHeaders.computeIfAbsent(
                        lower,
                        k -> new HeaderNameGroup(name, HeaderType.RESPONSE)
                );
                group.addHeaderValue(idGen, h.value(), domain, item, url, method, statusCode);
            }
        }
    }

    public synchronized void clear() {
        requestHeaders.clear();
        responseHeaders.clear();
        totalMessagesProcessed = 0;
        idGen.set(1);
    }

    public synchronized List<HeaderNameGroup> getFilteredGroups(
            HeaderType typeFilter,
            String domainFilter,
            String searchFilter) {
        List<HeaderNameGroup> result = new ArrayList<>();

        if (typeFilter == null || typeFilter == HeaderType.REQUEST) {
            for (HeaderNameGroup g : requestHeaders.values()) {
                if (g.matches(domainFilter, searchFilter)) {
                    result.add(g);
                }
            }
        }

        if (typeFilter == null || typeFilter == HeaderType.RESPONSE) {
            for (HeaderNameGroup g : responseHeaders.values()) {
                if (g.matches(domainFilter, searchFilter)) {
                    result.add(g);
                }
            }
        }

        // Sort by header name alphabetically, or occurrences descending
        result.sort((a, b) -> a.displayName().compareToIgnoreCase(b.displayName()));
        return result;
    }

    public synchronized int totalHeadersCount() {
        return requestHeaders.size() + responseHeaders.size();
    }

    public synchronized int totalUniqueValuesCount() {
        int count = 0;
        for (HeaderNameGroup g : requestHeaders.values()) {
            count += g.uniqueValuesCount();
        }
        for (HeaderNameGroup g : responseHeaders.values()) {
            count += g.uniqueValuesCount();
        }
        return count;
    }

    public synchronized int totalDomainsCount() {
        Set<String> all = new HashSet<>();
        for (HeaderNameGroup g : requestHeaders.values()) {
            all.addAll(g.allDomains());
        }
        for (HeaderNameGroup g : responseHeaders.values()) {
            all.addAll(g.allDomains());
        }
        return all.size();
    }

    public synchronized int totalMessagesProcessed() {
        return totalMessagesProcessed;
    }
}
