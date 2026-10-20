// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class OAuthDataStore {

    public interface DataStoreListener {
        void onEntryAdded(OAuthRequestEntry entry);
        void onEntryUpdated(OAuthRequestEntry entry);
        void onStoreCleared();
    }

    private final List<OAuthRequestEntry> entries;
    private final List<DataStoreListener> listeners;
    private final AtomicInteger sequenceCounter;

    public OAuthDataStore() {
        this.entries = new CopyOnWriteArrayList<>();
        this.listeners = new CopyOnWriteArrayList<>();
        this.sequenceCounter = new AtomicInteger(1);
    }

    public void addListener(DataStoreListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(DataStoreListener listener) {
        listeners.remove(listener);
    }

    public int nextId() {
        return sequenceCounter.getAndIncrement();
    }

    public synchronized void setNextId(int nextId) {
        sequenceCounter.set(Math.max(1, nextId));
    }

    public void addEntry(OAuthRequestEntry entry) {
        if (entry == null) return;
        entries.add(entry);
        for (DataStoreListener listener : listeners) {
            listener.onEntryAdded(entry);
        }
    }

    public void notifyUpdated(OAuthRequestEntry entry) {
        if (entry == null) return;
        for (DataStoreListener listener : listeners) {
            listener.onEntryUpdated(entry);
        }
    }

    public void clear() {
        entries.clear();
        for (DataStoreListener listener : listeners) {
            listener.onStoreCleared();
        }
    }

    public List<OAuthRequestEntry> getAllEntries() {
        return Collections.unmodifiableList(new ArrayList<>(entries));
    }

    public int size() {
        return entries.size();
    }

    public OAuthRequestEntry getById(int id) {
        for (OAuthRequestEntry e : entries) {
            if (e.getId() == id) {
                return e;
            }
        }
        return null;
    }

    public List<OAuthRequestEntry> getFilteredEntries(String textFilter, Set<String> flowFilters, Set<String> severityFilters) {
        String cleanText = (textFilter != null) ? textFilter.trim().toLowerCase() : "";

        return entries.stream().filter(entry -> {
            // Text search
            if (!cleanText.isEmpty()) {
                boolean matches = entry.getMethod().toLowerCase().contains(cleanText)
                        || entry.getHost().toLowerCase().contains(cleanText)
                        || entry.getPath().toLowerCase().contains(cleanText)
                        || entry.getUrl().toLowerCase().contains(cleanText)
                        || entry.getClientId().toLowerCase().contains(cleanText)
                        || entry.getRedirectUri().toLowerCase().contains(cleanText)
                        || entry.getFlowType().getDisplayName().toLowerCase().contains(cleanText)
                        || entry.getIssueSummary().toLowerCase().contains(cleanText);
                if (!matches) {
                    return false;
                }
            }

            // Flow filter
            if (flowFilters != null && !flowFilters.isEmpty()) {
                String flowName = entry.getFlowType().getDisplayName();
                if (!flowFilters.contains(flowName)) {
                    return false;
                }
            }

            // Severity filter
            if (severityFilters != null && !severityFilters.isEmpty()) {
                String sevLabel = entry.getHighestSeverity().getLabel();
                if (!severityFilters.contains(sevLabel)) {
                    return false;
                }
            }

            return true;
        }).collect(Collectors.toList());
    }
}
