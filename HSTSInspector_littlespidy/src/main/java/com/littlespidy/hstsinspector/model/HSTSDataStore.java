// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.model;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * Central thread-safe data store for HSTS entries with deduplication,
 * multi-dimensional grouping by directive/value, and fast triage filtering.
 *
 * @author littlespidy
 */
public class HSTSDataStore {

    /** Inspect modes exposed to the UI. */
    public static final String MODE_FULL          = "Full Header";
    public static final String MODE_MAX_AGE       = "max-age";
    public static final String MODE_SUBDOMAINS    = "includeSubDomains";
    public static final String MODE_PRELOAD       = "preload";
    public static final String MODE_MISSING       = "Missing HSTS";
    public static final String MODE_ASSESSMENT    = "Assessment";

    private final Map<String, HSTSEntry> entriesByKey = new LinkedHashMap<>();
    private final List<Runnable> listeners            = new ArrayList<>();
    private final AtomicInteger idCounter             = new AtomicInteger(1);

    // ── Identity / ID ────────────────────────────────────────────────────────

    public static String dedupeKey(HSTSEntry e) {
        if (e == null) return "";
        String m = (e.method() != null) ? e.method().toUpperCase() : "GET";
        return m + " " + e.url();
    }

    public int nextId() { return idCounter.getAndIncrement(); }

    // ── Mutation ─────────────────────────────────────────────────────────────

    public synchronized void addEntries(List<HSTSEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        for (HSTSEntry e : entries) {
            if (e != null) entriesByKey.put(dedupeKey(e), e);
        }
        notifyListeners();
    }

    public synchronized int size()                     { return entriesByKey.size(); }
    public synchronized List<HSTSEntry> getEntries()   { return new ArrayList<>(entriesByKey.values()); }

    public synchronized void clear() {
        entriesByKey.clear();
        idCounter.set(1);
        notifyListeners();
    }

    // ── Static filter helpers ─────────────────────────────────────────────────

    /**
     * Returns true when the entry's HTTP method is in the selected set,
     * or when the set is null/empty (meaning "all methods").
     */
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

    private static boolean matchesText(String source, String filter) {
        if (filter == null || filter.isBlank()) return true;
        if (source == null) return false;
        return source.toLowerCase().contains(filter.trim().toLowerCase());
    }

    // ── Grouping & Filtering ──────────────────────────────────────────────────

    /**
     * Groups entries by the selected inspection mode, applying all active filters.
     * The returned map keys are the "pattern" shown in the Summary table.
     */
    public synchronized Map<String, List<HSTSEntry>> groupByMode(
            String mode,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        Map<String, List<HSTSEntry>> groups = new LinkedHashMap<>();
        String m = mode != null ? mode.trim() : MODE_FULL;

        for (HSTSEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) continue;
            if (!matchesStatusCode(entry.statusCode(), statusFilter))    continue;
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) continue;
            if (!matchesMethod(entry.method(), methodFilter))             continue;

            String key = deriveGroupKey(m, entry);
            if (key != null && matchesText(key, valueFilter)) {
                groups.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
            }
        }
        return groups;
    }

    /** Returns entries matching all active filters, optionally narrowed to a specific summary-row value. */
    public synchronized List<HSTSEntry> getFilteredEntries(
            String mode,
            String selectedSummaryValue,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        List<HSTSEntry> list = new ArrayList<>();
        String m = mode != null ? mode.trim() : MODE_FULL;

        for (HSTSEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) continue;
            if (!matchesStatusCode(entry.statusCode(), statusFilter))    continue;
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) continue;
            if (!matchesMethod(entry.method(), methodFilter))             continue;

            String key = deriveGroupKey(m, entry);

            if (selectedSummaryValue != null) {
                if (selectedSummaryValue.equals(key)) list.add(entry);
            } else {
                if (matchesText(key, valueFilter)) list.add(entry);
            }
        }
        return list;
    }

    /**
     * Derives the grouping key for an entry in the given inspect mode.
     * Returns null if the entry should be excluded in this mode.
     */
    private static String deriveGroupKey(String mode, HSTSEntry e) {
        return switch (mode) {
            case MODE_FULL -> e.isMissingHsts() ? "(missing HSTS)" : e.hstsHeader().trim();
            case MODE_MAX_AGE -> {
                if (e.isMissingHsts()) yield "(missing HSTS)";
                if (e.maxAge() < 0)    yield "(not set)";
                yield "max-age=" + e.maxAge() + "  (" + e.maxAgeSummary() + ")";
            }
            case MODE_SUBDOMAINS -> {
                if (e.isMissingHsts()) yield "(missing HSTS)";
                yield e.includeSubDomains() ? "includeSubDomains: present" : "includeSubDomains: absent";
            }
            case MODE_PRELOAD -> {
                if (e.isMissingHsts()) yield "(missing HSTS)";
                yield e.preload() ? "preload: present" : "preload: absent";
            }
            case MODE_MISSING -> e.isMissingHsts() ? "(missing HSTS)" : null; // exclude non-missing
            case MODE_ASSESSMENT -> e.assessment();
            default -> e.isMissingHsts() ? "(missing HSTS)" : e.hstsHeader().trim();
        };
    }

    // ── Listeners ─────────────────────────────────────────────────────────────

    public void addListener(Runnable listener) {
        synchronized (listeners) { listeners.add(listener); }
    }

    private void notifyListeners() {
        List<Runnable> copy;
        synchronized (listeners) { copy = new ArrayList<>(listeners); }
        for (Runnable r : copy) r.run();
    }
}
