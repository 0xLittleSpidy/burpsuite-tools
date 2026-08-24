// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Central thread-safe data store for JavaScript script entries with automatic URL deduplication,
 * origin filtering, and listener notification.
 *
 * @author littlespidy
 */
public class JsDataStore {

    private final List<JsFileEntry> entries = new ArrayList<>();
    private final Set<String> knownUrls = new HashSet<>();
    private final List<Runnable> listeners = new ArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(1);

    public int nextId() {
        return idCounter.getAndIncrement();
    }

    public synchronized boolean addEntry(JsFileEntry entry) {
        if (entry == null || entry.getUrl() == null) {
            return false;
        }

        String normalized = normalizeUrl(entry.getUrl());
        if (knownUrls.contains(normalized)) {
            return false;
        }

        knownUrls.add(normalized);
        entries.add(entry);
        notifyListeners();
        return true;
    }

    public synchronized void addEntries(List<JsFileEntry> newEntries) {
        if (newEntries == null || newEntries.isEmpty()) return;
        boolean added = false;
        for (JsFileEntry entry : newEntries) {
            if (entry != null && entry.getUrl() != null) {
                String normalized = normalizeUrl(entry.getUrl());
                if (!knownUrls.contains(normalized)) {
                    knownUrls.add(normalized);
                    entries.add(entry);
                    added = true;
                }
            }
        }
        if (added) {
            notifyListeners();
        }
    }

    public synchronized List<JsFileEntry> getEntries() {
        return new ArrayList<>(entries);
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized void clear() {
        entries.clear();
        knownUrls.clear();
        idCounter.set(1);
        notifyListeners();
    }

    public void addListener(Runnable listener) {
        synchronized (listeners) {
            listeners.add(listener);
        }
    }

    public void notifyListeners() {
        List<Runnable> copy;
        synchronized (listeners) {
            copy = new ArrayList<>(listeners);
        }
        for (Runnable r : copy) {
            r.run();
        }
    }

    public static String normalizeUrl(String url) {
        if (url == null) return "";
        String trimmed = url.trim();
        int hashIdx = trimmed.indexOf('#');
        if (hashIdx != -1) {
            trimmed = trimmed.substring(0, hashIdx);
        }
        return trimmed;
    }
}
