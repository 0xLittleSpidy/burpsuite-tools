// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe central data store for HTTP status codes collected from Proxy responses.
 * Groups endpoints, request methods, and target hosts under unique HTTP status codes,
 * tracks response counts, and enables filtering by domain, status class, and search keywords.
 *
 * @author littlespidy
 */
public class StatusCollectorDataStore {

    private final Map<Integer, StatusGroup> statusGroups = new TreeMap<>();
    private final AtomicInteger idGen = new AtomicInteger(1);
    private int totalResponsesProcessed = 0;

    public synchronized void ingest(ProxyHttpRequestResponse item) {
        if (item == null || !item.hasResponse() || item.response() == null) return;
        totalResponsesProcessed++;

        int statusCode = item.response().statusCode();
        if (statusCode <= 0) return;

        String method = (item.request() != null && item.request().method() != null) ? item.request().method().toUpperCase(Locale.ROOT).trim() : "GET";
        String url = (item.request() != null && item.request().url() != null) ? item.request().url() : "";
        String path = (item.request() != null && item.request().path() != null) ? item.request().path() : "/";
        String domain = "";
        if (item.request() != null && item.request().httpService() != null && item.request().httpService().host() != null) {
            domain = item.request().httpService().host();
        }

        StatusGroup group = statusGroups.computeIfAbsent(statusCode, StatusGroup::new);
        group.addEndpoint(idGen, method, url, path, domain, item);
    }

    public synchronized void clear() {
        statusGroups.clear();
        totalResponsesProcessed = 0;
        idGen.set(1);
    }

    public synchronized List<StatusGroup> getFilteredGroups(
            String domainFilter,
            String searchFilter,
            String classFilter) {

        List<StatusGroup> result = new ArrayList<>();
        for (StatusGroup g : statusGroups.values()) {
            if (g.matches(domainFilter, searchFilter, classFilter)) {
                result.add(g);
            }
        }

        // Sort by status code numerically
        result.sort(Comparator.comparingInt(StatusGroup::statusCode));
        return result;
    }

    public synchronized int totalStatusCodesCount() {
        return statusGroups.size();
    }

    public synchronized int totalResponsesCount() {
        int sum = 0;
        for (StatusGroup g : statusGroups.values()) {
            sum += g.totalResponses();
        }
        return sum;
    }

    public synchronized int totalDomainsCount() {
        Set<String> all = new HashSet<>();
        for (StatusGroup g : statusGroups.values()) {
            all.addAll(g.allDomains());
        }
        return all.size();
    }

    public synchronized int totalProcessed() {
        return totalResponsesProcessed;
    }
}
