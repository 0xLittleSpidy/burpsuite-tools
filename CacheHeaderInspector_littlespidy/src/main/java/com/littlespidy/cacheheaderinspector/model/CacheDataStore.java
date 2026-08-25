// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.model;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * Thread-safe central data store for captured cache header entries.
 * Deduplicates entries by HTTP method + URL, and supports listener notifications,
 * status code filtering, content-type filtering, and grouping by directive value.
 *
 * @author littlespidy
 */
public class CacheDataStore {

    private final Map<String, CacheEntry> entriesByKey = new LinkedHashMap<>();
    private final List<Runnable> listeners = new ArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(1);

    public static String dedupeKey(CacheEntry entry) {
        if (entry == null) return "";
        String method = (entry.request() != null && entry.request().method() != null)
                ? entry.request().method().toUpperCase()
                : "GET";
        return method + " " + entry.url();
    }

    public int nextId() {
        return idCounter.getAndIncrement();
    }

    public synchronized void addEntry(CacheEntry entry) {
        if (entry == null) return;
        entriesByKey.put(dedupeKey(entry), entry);
        notifyListeners();
    }

    public synchronized void addEntries(List<CacheEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        for (CacheEntry entry : entries) {
            if (entry != null) {
                entriesByKey.put(dedupeKey(entry), entry);
            }
        }
        notifyListeners();
    }

    public synchronized List<CacheEntry> getEntries() {
        return new ArrayList<>(entriesByKey.values());
    }

    public synchronized int size() {
        return entriesByKey.size();
    }

    /**
     * Helper to match status codes with support for dropdown presets (e.g. "2xx Success", "200 OK",
     * "301 / 302 Redirect"), comma-separated codes, and status families.
     */
    public static boolean matchesStatusCode(int statusCode, String filter) {
        if (filter == null || filter.trim().isEmpty()
                || filter.equalsIgnoreCase("All Status Codes") || filter.equalsIgnoreCase("All")) {
            return true;
        }
        String statusStr = String.valueOf(statusCode);
        String[] tokens = filter.split("[,/|\\s]+");
        for (String token : tokens) {
            token = token.trim();
            if (token.isEmpty()) continue;
            if (token.length() == 3 && (token.endsWith("xx") || token.endsWith("XX"))) {
                char prefix = token.charAt(0);
                if (statusStr.charAt(0) == prefix) {
                    return true;
                }
            } else if (statusStr.equals(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Helper to match Content-Type via preset keywords or case-insensitive substring search.
     */
    public static boolean matchesContentType(String contentType, String filter) {
        if (filter == null || filter.trim().isEmpty()
                || filter.equalsIgnoreCase("All Content-Types") || filter.equalsIgnoreCase("All")) {
            return true;
        }
        if (contentType == null) return false;
        String lowerContent = contentType.toLowerCase();
        String lowerFilter = filter.toLowerCase().trim();

        if (lowerFilter.contains("html")) return lowerContent.contains("html");
        if (lowerFilter.contains("json")) return lowerContent.contains("json");
        if (lowerFilter.contains("javascript") || lowerFilter.contains("js")) {
            return lowerContent.contains("javascript") || lowerContent.contains("ecmascript");
        }
        if (lowerFilter.contains("css")) return lowerContent.contains("css");
        if (lowerFilter.contains("xml")) return lowerContent.contains("xml");
        if (lowerFilter.contains("image")) return lowerContent.contains("image");
        if (lowerFilter.contains("plain")) return lowerContent.contains("plain");
        if (lowerFilter.contains("pdf")) return lowerContent.contains("pdf");

        return lowerContent.contains(lowerFilter);
    }

    /**
     * Groups entries by unique values of the specified header, applying status code,
     * content-type, in-scope, and directive text filters.
     */
    public synchronized Map<String, List<CacheEntry>> groupByDirectiveFiltered(
            String headerName,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Predicate<String> inScopePredicate) {

        Map<String, List<CacheEntry>> groups = new LinkedHashMap<>();
        for (CacheEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) {
                continue;
            }
            if (!matchesStatusCode(entry.statusCode(), statusFilter)) {
                continue;
            }
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) {
                continue;
            }

            String val = entry.getHeaderValue(headerName);
            if (val == null || val.trim().isEmpty()) {
                val = "(not set)";
            }
            if (valueFilter != null && !valueFilter.trim().isEmpty()
                    && !val.toLowerCase().contains(valueFilter.trim().toLowerCase())) {
                continue;
            }
            groups.computeIfAbsent(val, k -> new ArrayList<>()).add(entry);
        }
        return groups;
    }

    /**
     * Retrieves filtered entries for the URL table.
     */
    public synchronized List<CacheEntry> getFilteredEntries(
            String headerName,
            String exactDirectiveValue,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Predicate<String> inScopePredicate) {

        List<CacheEntry> filtered = new ArrayList<>();
        for (CacheEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) {
                continue;
            }
            if (!matchesStatusCode(entry.statusCode(), statusFilter)) {
                continue;
            }
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) {
                continue;
            }

            String val = entry.getHeaderValue(headerName);
            if (val == null || val.trim().isEmpty()) {
                val = "(not set)";
            }

            if (exactDirectiveValue != null) {
                if (val.equals(exactDirectiveValue)) {
                    filtered.add(entry);
                }
            } else {
                if (valueFilter == null || valueFilter.trim().isEmpty()
                        || val.toLowerCase().contains(valueFilter.trim().toLowerCase())) {
                    filtered.add(entry);
                }
            }
        }
        return filtered;
    }

    public synchronized void clear() {
        entriesByKey.clear();
        idCounter.set(1);
        notifyListeners();
    }

    public void addListener(Runnable listener) {
        synchronized (listeners) {
            listeners.add(listener);
        }
    }

    private void notifyListeners() {
        List<Runnable> copy;
        synchronized (listeners) {
            copy = new ArrayList<>(listeners);
        }
        for (Runnable r : copy) {
            r.run();
        }
    }
}

