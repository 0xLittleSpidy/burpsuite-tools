// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.cache.model;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Thread-safe central data store for captured cache header entries.
 * Deduplicates entries by HTTP method + URL, and supports listener notifications,
 * status code filtering, content-type filtering, method filtering, and grouping
 * by directive value.
 *
 * @author littlespidy
 */
public class CacheDataStore {

    private final Map<String, CacheEntry> entriesByKey = new LinkedHashMap<>();
    private final List<Runnable> listeners             = new ArrayList<>();
    private final AtomicInteger idCounter              = new AtomicInteger(1);

    public static String dedupeKey(CacheEntry entry) {
        if (entry == null) return "";
        String method = (entry.method() != null) ? entry.method().toUpperCase() : "GET";
        return method + " " + entry.url();
    }

    public int nextId() { return idCounter.getAndIncrement(); }

    public synchronized void addEntry(CacheEntry entry) {
        if (entry == null) return;
        entriesByKey.put(dedupeKey(entry), entry);
        notifyListeners();
    }

    public synchronized void addEntries(List<CacheEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        for (CacheEntry e : entries) {
            if (e != null) entriesByKey.put(dedupeKey(e), e);
        }
        notifyListeners();
    }

    public synchronized List<CacheEntry> getEntries() { return new ArrayList<>(entriesByKey.values()); }
    public synchronized int size()                    { return entriesByKey.size(); }

    // ── Static filter helpers ─────────────────────────────────────────────────

    public static boolean matchesMethod(String method, Set<String> selectedMethods) {
        if (selectedMethods == null || selectedMethods.isEmpty()) return true;
        if (method == null) return false;
        return selectedMethods.contains(method.toUpperCase());
    }

    public static boolean matchesStatusCode(int statusCode, String filter) {
        if (filter == null || filter.isBlank()
                || filter.equalsIgnoreCase("All Status Codes")
                || filter.equalsIgnoreCase("All")) return true;
        String s = String.valueOf(statusCode);
        for (String token : filter.split("[,/|\\s]+")) {
            token = token.trim();
            if (token.isEmpty()) continue;
            if (token.length() == 3 && (token.endsWith("xx") || token.endsWith("XX"))) {
                if (s.charAt(0) == token.charAt(0)) return true;
            } else if (s.equals(token)) return true;
        }
        return false;
    }

    public static boolean matchesContentType(String contentType, String filter) {
        if (filter == null || filter.isBlank()
                || filter.equalsIgnoreCase("All Content-Types")
                || filter.equalsIgnoreCase("All")) return true;
        if (contentType == null) return false;
        String lc = contentType.toLowerCase();
        String lf = filter.toLowerCase().trim();
        if (lf.contains("html"))       return lc.contains("html");
        if (lf.contains("json"))       return lc.contains("json");
        if (lf.contains("javascript") || lf.contains("js")) return lc.contains("javascript") || lc.contains("ecmascript");
        if (lf.contains("css"))        return lc.contains("css");
        if (lf.contains("xml"))        return lc.contains("xml");
        if (lf.contains("image"))      return lc.contains("image");
        if (lf.contains("plain"))      return lc.contains("plain");
        if (lf.contains("pdf"))        return lc.contains("pdf");
        return lc.contains(lf);
    }

    // ── Grouping & Filtering ──────────────────────────────────────────────────

    public synchronized Map<String, List<CacheEntry>> groupByDirectiveFiltered(
            String headerName,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        Map<String, List<CacheEntry>> groups = new LinkedHashMap<>();
        for (CacheEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) continue;
            if (!matchesStatusCode(entry.statusCode(), statusFilter))    continue;
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) continue;
            if (!matchesMethod(entry.method(), methodFilter))             continue;

            String val = entry.getHeaderValue(headerName);
            if (val == null || val.isBlank()) val = "(not set)";
            if (valueFilter != null && !valueFilter.isBlank()
                    && !val.toLowerCase().contains(valueFilter.trim().toLowerCase())) continue;

            groups.computeIfAbsent(val, k -> new ArrayList<>()).add(entry);
        }
        return groups;
    }

    public synchronized List<CacheEntry> getFilteredEntries(
            String headerName,
            String exactDirectiveValue,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        List<CacheEntry> filtered = new ArrayList<>();
        for (CacheEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) continue;
            if (!matchesStatusCode(entry.statusCode(), statusFilter))    continue;
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) continue;
            if (!matchesMethod(entry.method(), methodFilter))             continue;

            String val = entry.getHeaderValue(headerName);
            if (val == null || val.isBlank()) val = "(not set)";

            if (exactDirectiveValue != null) {
                if (val.equals(exactDirectiveValue)) filtered.add(entry);
            } else {
                if (valueFilter == null || valueFilter.isBlank()
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
        synchronized (listeners) { listeners.add(listener); }
    }

    private void notifyListeners() {
        List<Runnable> copy;
        synchronized (listeners) { copy = new ArrayList<>(listeners); }
        for (Runnable r : copy) r.run();
    }
}
