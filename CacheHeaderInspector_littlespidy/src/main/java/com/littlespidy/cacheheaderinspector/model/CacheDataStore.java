// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.model;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Thread-safe central data store for captured cache header entries.
 * Supports listener notifications, filtering, and grouping by directive value.
 *
 * @author littlespidy
 */
public class CacheDataStore {

    private final List<CacheEntry> allEntries = new ArrayList<>();
    private final List<Runnable> listeners = new ArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(1);

    public int nextId() {
        return idCounter.getAndIncrement();
    }

    public synchronized void addEntry(CacheEntry entry) {
        allEntries.add(entry);
        notifyListeners();
    }

    public synchronized void addEntries(List<CacheEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        allEntries.addAll(entries);
        notifyListeners();
    }

    public synchronized List<CacheEntry> getEntries() {
        return new ArrayList<>(allEntries);
    }

    public synchronized int size() {
        return allEntries.size();
    }

    /**
     * Returns entries where the specified header contains the filter string (case-insensitive).
     */
    public synchronized List<CacheEntry> filterByHeaderAndValue(String headerName, String valueFilter) {
        List<CacheEntry> filtered = new ArrayList<>();
        for (CacheEntry entry : allEntries) {
            String val = entry.getHeaderValue(headerName);
            if (val != null && !val.isEmpty()
                    && val.toLowerCase().contains(valueFilter.toLowerCase())) {
                filtered.add(entry);
            }
        }
        return filtered;
    }

    /**
     * Groups all entries by unique values of the specified header.
     * Entries with empty/missing header are grouped under "(not set)".
     */
    public synchronized Map<String, List<CacheEntry>> groupByDirective(String headerName) {
        Map<String, List<CacheEntry>> groups = new LinkedHashMap<>();
        for (CacheEntry entry : allEntries) {
            String val = entry.getHeaderValue(headerName);
            if (val == null || val.trim().isEmpty()) {
                val = "(not set)";
            }
            groups.computeIfAbsent(val, k -> new ArrayList<>()).add(entry);
        }
        return groups;
    }

    /**
     * Groups entries by unique values of the specified header, keeping only values
     * whose text contains the given filter substring (case-insensitive).
     */
    public synchronized Map<String, List<CacheEntry>> groupByDirectiveFiltered(
            String headerName, String valueFilter) {

        Map<String, List<CacheEntry>> groups = new LinkedHashMap<>();
        for (CacheEntry entry : allEntries) {
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

    public synchronized void clear() {
        allEntries.clear();
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
