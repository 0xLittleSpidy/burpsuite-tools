// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.model;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Thread-safe repository storing scan activity entries with capacity capping,
 * filtering, listeners, and TSV export.
 *
 * @author littlespidy
 */
public class ScanActivityDataStore {

    private static final int MAX_ENTRIES = 5000;
    private final List<ScanActivityEntry> entries = new ArrayList<>();
    private final AtomicLong idCounter = new AtomicLong(1);
    private final List<Consumer<ScanActivityEntry>> listeners = new CopyOnWriteArrayList<>();

    public synchronized void addEntry(ScanActivityEntry entry) {
        if (entries.size() >= MAX_ENTRIES) {
            entries.remove(0);
        }
        entries.add(entry);
        notifyListeners(entry);
    }

    public long nextId() {
        return idCounter.getAndIncrement();
    }

    public synchronized void clear() {
        entries.clear();
        notifyListeners(null);
    }

    public synchronized List<ScanActivityEntry> getEntries() {
        return new ArrayList<>(entries);
    }

    public synchronized int size() {
        return entries.size();
    }

    public void addListener(Consumer<ScanActivityEntry> listener) {
        listeners.add(listener);
    }

    public void removeListener(Consumer<ScanActivityEntry> listener) {
        listeners.remove(listener);
    }

    private void notifyListeners(ScanActivityEntry entry) {
        for (Consumer<ScanActivityEntry> listener : listeners) {
            try {
                listener.accept(entry);
            } catch (Exception ignored) {}
        }
    }

    public synchronized List<ScanActivityEntry> getFilteredEntries(
            String searchText,
            Set<String> toolFilter,
            Set<String> statusFilter,
            Set<String> actionFilter) {

        List<ScanActivityEntry> result = new ArrayList<>();
        String query = (searchText != null) ? searchText.trim().toLowerCase(Locale.ROOT) : "";

        for (ScanActivityEntry entry : entries) {
            // Tool filter
            if (toolFilter != null && !toolFilter.isEmpty()) {
                if (!toolFilter.contains(entry.getTool())) {
                    continue;
                }
            }

            // Status filter (e.g. "2xx", "3xx", "4xx", "5xx")
            if (statusFilter != null && !statusFilter.isEmpty()) {
                String sc = String.valueOf(entry.getStatusCode());
                String group = sc.length() >= 1 ? sc.charAt(0) + "xx" : "Other";
                if (!statusFilter.contains(group) && !statusFilter.contains(sc)) {
                    continue;
                }
            }

            // Action / Event filter
            if (actionFilter != null && !actionFilter.isEmpty()) {
                if (!actionFilter.contains(entry.getEventType())) {
                    continue;
                }
            }

            // Search query
            if (!query.isEmpty()) {
                boolean matches = entry.getUrl().toLowerCase(Locale.ROOT).contains(query)
                        || entry.getHost().toLowerCase(Locale.ROOT).contains(query)
                        || entry.getDetails().toLowerCase(Locale.ROOT).contains(query)
                        || entry.getEventType().toLowerCase(Locale.ROOT).contains(query)
                        || String.valueOf(entry.getStatusCode()).contains(query);
                if (!matches) {
                    continue;
                }
            }

            result.add(entry);
        }

        return result;
    }

    public synchronized String exportToTsv() {
        StringBuilder sb = new StringBuilder();
        sb.append("ID\tTimestamp\tTool\tMethod\tHost\tURL\tStatus\tEvent\tDetails\n");
        for (ScanActivityEntry e : entries) {
            sb.append(e.getId()).append("\t")
              .append(e.getTimestamp()).append("\t")
              .append(e.getTool()).append("\t")
              .append(e.getMethod()).append("\t")
              .append(e.getHost()).append("\t")
              .append(e.getUrl()).append("\t")
              .append(e.getStatusCode()).append("\t")
              .append(e.getEventType()).append("\t")
              .append(e.getDetails().replace("\t", " ").replace("\n", " "))
              .append("\n");
        }
        return sb.toString();
    }
}
