// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Thread-safe datastore storing and filtering findings for a specific category.
 */
public class InspectorDataStore {

    private final FindingCategory category;
    private final AtomicInteger idCounter = new AtomicInteger(1);
    private final Map<String, FindingEntry> entriesByKey = new LinkedHashMap<>();
    private final List<FindingEntry> allEntries = new ArrayList<>();
    private final Set<Integer> pinnedIds = Collections.synchronizedSet(new LinkedHashSet<>());

    public InspectorDataStore(FindingCategory category) {
        this.category = category;
    }

    public FindingCategory getCategory() {
        return category;
    }

    /**
     * Adds an entry if not already present based on dedupeKey.
     *
     * @return true if newly added, false if duplicate
     */
    public synchronized boolean addEntry(FindingEntry entry) {
        String key = entry.dedupeKey();
        if (entriesByKey.containsKey(key)) {
            return false;
        }
        entriesByKey.put(key, entry);
        allEntries.add(entry);
        return true;
    }

    public synchronized int nextId() {
        return idCounter.getAndIncrement();
    }

    public synchronized void clear() {
        entriesByKey.clear();
        allEntries.clear();
        pinnedIds.clear();
        idCounter.set(1);
    }

    public synchronized int size() {
        return allEntries.size();
    }

    public synchronized List<FindingEntry> getAllEntries() {
        return new ArrayList<>(allEntries);
    }

    // ─── Pinning Support ────────────────────────────────────────────────────────

    public boolean isPinned(int entryId) {
        return pinnedIds.contains(entryId);
    }

    public void pin(int entryId) {
        pinnedIds.add(entryId);
    }

    public void unpin(int entryId) {
        pinnedIds.remove(entryId);
    }

    public void clearPins() {
        pinnedIds.clear();
    }

    public boolean hasPins() {
        return !pinnedIds.isEmpty();
    }

    public int getPinnedCount() {
        return pinnedIds.size();
    }

    // ─── Filtering API ──────────────────────────────────────────────────────────

    /**
     * Filters entries based on current search term, status codes, content types, methods, scope, and selected in-scope domains.
     * Complies with the standard method filter signature requirement.
     */
    public synchronized List<FindingEntry> getFilteredEntries(
            String searchTerm,
            Set<String> statusFilter,
            Set<String> contentTypeFilter,
            Set<String> methodFilter,
            Set<String> patternFilter,
            boolean inScopeOnly,
            Predicate<String> inScopePredicate,
            InScopeDomainManager domainManager
    ) {
        // If items are pinned, pinning overrides other filters to isolate pinned items
        if (hasPins()) {
            return allEntries.stream()
                    .filter(e -> pinnedIds.contains(e.id()))
                    .collect(Collectors.toList());
        }

        String searchLower = (searchTerm != null) ? searchTerm.trim().toLowerCase() : "";

        return allEntries.stream()
                .filter(e -> {
                    // Scope filter
                    if (inScopeOnly && inScopePredicate != null && !e.url().isEmpty()) {
                        if (!inScopePredicate.test(e.url())) {
                            return false;
                        }
                    }

                    // Domain selection filter
                    if (inScopeOnly && domainManager != null && !e.host().isEmpty()) {
                        if (!domainManager.matchesDomain(e.host())) {
                            return false;
                        }
                    }

                    // Pattern / Secret Type filter
                    if (patternFilter != null && !patternFilter.isEmpty()) {
                        if (!patternFilter.contains(e.patternName())) {
                            return false;
                        }
                    }

                    // Method filter
                    if (!matchesMethod(e.method(), methodFilter)) {
                        return false;
                    }

                    // Status code filter
                    if (!matchesStatus(e.statusCode(), statusFilter)) {
                        return false;
                    }

                    // Content-Type filter
                    if (!matchesContentType(e.contentType(), contentTypeFilter)) {
                        return false;
                    }

                    // Freeform text search
                    if (!searchLower.isEmpty()) {
                        boolean match = e.url().toLowerCase().contains(searchLower)
                                || e.patternName().toLowerCase().contains(searchLower)
                                || e.matchValue().toLowerCase().contains(searchLower)
                                || e.matchLocation().toLowerCase().contains(searchLower)
                                || e.method().toLowerCase().contains(searchLower)
                                || String.valueOf(e.statusCode()).contains(searchLower);
                        if (!match) return false;
                    }

                    return true;
                })
                .collect(Collectors.toList());
    }

    public synchronized List<FindingEntry> getFilteredEntries(
            String searchTerm,
            Set<String> statusFilter,
            Set<String> contentTypeFilter,
            Set<String> methodFilter,
            boolean inScopeOnly,
            Predicate<String> inScopePredicate,
            InScopeDomainManager domainManager
    ) {
        return getFilteredEntries(searchTerm, statusFilter, contentTypeFilter, methodFilter, null, inScopeOnly, inScopePredicate, domainManager);
    }

    public synchronized List<FindingEntry> getFilteredEntries(
            String searchTerm,
            Set<String> statusFilter,
            Set<String> contentTypeFilter,
            Set<String> methodFilter,
            boolean inScopeOnly,
            Predicate<String> inScopePredicate
    ) {
        return getFilteredEntries(searchTerm, statusFilter, contentTypeFilter, methodFilter, inScopeOnly, inScopePredicate, null);
    }

    /**
     * Standard method matcher helper.
     */
    public static boolean matchesMethod(String method, Set<String> selectedMethods) {
        if (selectedMethods == null || selectedMethods.isEmpty()) return true;
        if (method == null) return false;
        return selectedMethods.contains(method.toUpperCase());
    }

    private static boolean matchesStatus(short statusCode, Set<String> selectedStatuses) {
        if (selectedStatuses == null || selectedStatuses.isEmpty()) return true;
        String codeStr = String.valueOf(statusCode);
        for (String sel : selectedStatuses) {
            if (sel.equalsIgnoreCase(codeStr)) return true;
            if (sel.equalsIgnoreCase("2xx") && statusCode >= 200 && statusCode < 300) return true;
            if (sel.equalsIgnoreCase("3xx") && statusCode >= 300 && statusCode < 400) return true;
            if (sel.equalsIgnoreCase("4xx") && statusCode >= 400 && statusCode < 500) return true;
            if (sel.equalsIgnoreCase("5xx") && statusCode >= 500 && statusCode < 600) return true;
        }
        return false;
    }

    private static boolean matchesContentType(String contentType, Set<String> selectedTypes) {
        if (selectedTypes == null || selectedTypes.isEmpty()) return true;
        if (contentType == null) return false;
        String ctLower = contentType.toLowerCase();
        for (String sel : selectedTypes) {
            String selLower = sel.toLowerCase();
            if (selLower.contains("json") && ctLower.contains("json")) return true;
            if (selLower.contains("html") && ctLower.contains("html")) return true;
            if (selLower.contains("javascript") && (ctLower.contains("javascript") || ctLower.contains("ecmascript"))) return true;
            if (selLower.contains("xml") && ctLower.contains("xml")) return true;
            if (selLower.contains("plain") && ctLower.contains("plain")) return true;
            if (ctLower.contains(selLower)) return true;
        }
        return false;
    }
}
