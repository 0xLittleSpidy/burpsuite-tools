// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe central data store for HTTP methods collected from Proxy traffic.
 * Groups endpoints and target hosts under unique HTTP methods, tracks request counts,
 * and enables filtering by domain, method name, RFC safety, and cacheability.
 *
 * @author littlespidy
 */
public class MethodCollectorDataStore {

    private final Map<String, MethodGroup> methodGroups = new LinkedHashMap<>();
    private final AtomicInteger idGen = new AtomicInteger(1);
    private int totalRequestsProcessed = 0;

    public synchronized void ingest(ProxyHttpRequestResponse item) {
        if (item == null || item.request() == null) return;
        totalRequestsProcessed++;

        String method = item.request().method() != null ? item.request().method().toUpperCase(Locale.ROOT).trim() : "GET";
        String url = item.request().url() != null ? item.request().url() : "";
        String path = item.request().path() != null ? item.request().path() : "/";
        String domain = "";
        if (item.request().httpService() != null && item.request().httpService().host() != null) {
            domain = item.request().httpService().host();
        }

        int statusCode = (item.hasResponse() && item.response() != null) ? item.response().statusCode() : 0;

        MethodGroup group = methodGroups.computeIfAbsent(method, MethodGroup::new);
        group.addEndpoint(idGen, url, path, domain, statusCode, item);
    }

    public synchronized void clear() {
        methodGroups.clear();
        totalRequestsProcessed = 0;
        idGen.set(1);
    }

    public synchronized List<MethodGroup> getFilteredGroups(
            String domainFilter,
            String searchFilter,
            String safetyFilter,
            String cacheableFilter) {

        List<MethodGroup> result = new ArrayList<>();
        for (MethodGroup g : methodGroups.values()) {
            if (g.matches(domainFilter, searchFilter, safetyFilter, cacheableFilter)) {
                result.add(g);
            }
        }

        // Sort by total requests descending
        result.sort((a, b) -> Integer.compare(b.totalRequests(), a.totalRequests()));
        return result;
    }

    public synchronized int totalMethodsCount() {
        return methodGroups.size();
    }

    public synchronized int totalRequestsCount() {
        int sum = 0;
        for (MethodGroup g : methodGroups.values()) {
            sum += g.totalRequests();
        }
        return sum;
    }

    public synchronized int totalDomainsCount() {
        Set<String> all = new HashSet<>();
        for (MethodGroup g : methodGroups.values()) {
            all.addAll(g.allDomains());
        }
        return all.size();
    }

    public synchronized int totalProcessed() {
        return totalRequestsProcessed;
    }
}
