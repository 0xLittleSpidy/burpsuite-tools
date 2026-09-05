// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.model;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * Central thread-safe data store for CSP entries with deduplication,
 * multi-dimensional grouping by directive/value, and fast triage filtering.
 *
 * @author littlespidy
 */
public class CSPDataStore {

    private final Map<String, CSPEntry> entriesByKey = new LinkedHashMap<>();
    private final List<Runnable> listeners = new ArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(1);

    public static String dedupeKey(CSPEntry entry) {
        if (entry == null) return "";
        String method = (entry.method() != null) ? entry.method().toUpperCase() : "GET";
        return method + " " + entry.url();
    }

    public int nextId() {
        return idCounter.getAndIncrement();
    }

    public synchronized void addEntry(CSPEntry entry) {
        if (entry == null) return;
        entriesByKey.put(dedupeKey(entry), entry);
        notifyListeners();
    }

    public synchronized void addEntries(List<CSPEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        for (CSPEntry entry : entries) {
            if (entry != null) {
                entriesByKey.put(dedupeKey(entry), entry);
            }
        }
        notifyListeners();
    }

    public synchronized List<CSPEntry> getEntries() {
        return new ArrayList<>(entriesByKey.values());
    }

    public synchronized int size() {
        return entriesByKey.size();
    }

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
     * Groups entries based on the selected inspection mode (Full Policy, specific directive, or individual sources)
     * and applies status code, content-type, in-scope, and keyword filters.
     */
    public synchronized Map<String, List<CSPEntry>> groupByMode(
            String mode,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        Map<String, List<CSPEntry>> groups = new LinkedHashMap<>();
        String normalizedMode = mode != null ? mode.trim() : "Full Policy";

        for (CSPEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) continue;
            if (!matchesStatusCode(entry.statusCode(), statusFilter)) continue;
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) continue;
            if (!matchesMethod(entry.method(), methodFilter)) continue;


            if (normalizedMode.equalsIgnoreCase("Full Policy")) {
                String fullPolicy = entry.getPrimaryCsp();
                if (matchesText(fullPolicy, valueFilter)) {
                    groups.computeIfAbsent(fullPolicy, k -> new ArrayList<>()).add(entry);
                }
            } else if (normalizedMode.equalsIgnoreCase("CSP-Report-Only")) {
                String ro = (entry.cspReportOnlyHeader() != null && !entry.cspReportOnlyHeader().trim().isEmpty())
                        ? entry.cspReportOnlyHeader().trim()
                        : "(not set)";
                if (matchesText(ro, valueFilter)) {
                    groups.computeIfAbsent(ro, k -> new ArrayList<>()).add(entry);
                }
            } else if (normalizedMode.equalsIgnoreCase("All Sources (Directives)")) {
                // Group by every unique token across all directives
                if (entry.isMissingCsp()) {
                    if (matchesText("(missing CSP)", valueFilter)) {
                        groups.computeIfAbsent("(missing CSP)", k -> new ArrayList<>()).add(entry);
                    }
                } else {
                    Set<String> seenTokens = new HashSet<>();
                    for (Map.Entry<String, List<String>> dir : entry.parsedDirectives().entrySet()) {
                        String directiveName = dir.getKey();
                        for (String token : dir.getValue()) {
                            String itemKey = directiveName + " " + token;
                            if (seenTokens.add(itemKey) && matchesText(itemKey, valueFilter)) {
                                groups.computeIfAbsent(itemKey, k -> new ArrayList<>()).add(entry);
                            }
                        }
                    }
                }
            } else {
                // Specific directive name (e.g. script-src, default-src, frame-ancestors)
                String dirVal = entry.getDirectiveString(normalizedMode);
                if (matchesText(dirVal, valueFilter)) {
                    groups.computeIfAbsent(dirVal, k -> new ArrayList<>()).add(entry);
                }
            }
        }

        return groups;
    }

    /**
     * Returns matching entries for display in the detailed URL table.
     */
    public synchronized List<CSPEntry> getFilteredEntries(
            String mode,
            String selectedSummaryValue,
            String valueFilter,
            String statusFilter,
            String contentTypeFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        List<CSPEntry> list = new ArrayList<>();
        String normalizedMode = mode != null ? mode.trim() : "Full Policy";

        for (CSPEntry entry : entriesByKey.values()) {
            if (inScopePredicate != null && !inScopePredicate.test(entry.url())) continue;
            if (!matchesStatusCode(entry.statusCode(), statusFilter)) continue;
            if (!matchesContentType(entry.contentType(), contentTypeFilter)) continue;
            if (!matchesMethod(entry.method(), methodFilter)) continue;

            if (selectedSummaryValue != null) {
                // Exact row match from summary table
                if (normalizedMode.equalsIgnoreCase("Full Policy")) {
                    if (entry.getPrimaryCsp().equals(selectedSummaryValue)) {
                        list.add(entry);
                    }
                } else if (normalizedMode.equalsIgnoreCase("CSP-Report-Only")) {
                    String ro = (entry.cspReportOnlyHeader() != null && !entry.cspReportOnlyHeader().trim().isEmpty())
                            ? entry.cspReportOnlyHeader().trim()
                            : "(not set)";
                    if (ro.equals(selectedSummaryValue)) {
                        list.add(entry);
                    }
                } else if (normalizedMode.equalsIgnoreCase("All Sources (Directives)")) {
                    if (selectedSummaryValue.equals("(missing CSP)")) {
                        if (entry.isMissingCsp()) list.add(entry);
                    } else {
                        String[] parts = selectedSummaryValue.split("\\s+", 2);
                        if (parts.length == 2 && entry.directiveContains(parts[0], parts[1])) {
                            list.add(entry);
                        }
                    }
                } else {
                    if (entry.getDirectiveString(normalizedMode).equals(selectedSummaryValue)) {
                        list.add(entry);
                    }
                }
            } else {
                // Freeform filter match
                if (normalizedMode.equalsIgnoreCase("Full Policy")) {
                    if (matchesText(entry.getPrimaryCsp(), valueFilter)) list.add(entry);
                } else if (normalizedMode.equalsIgnoreCase("CSP-Report-Only")) {
                    String ro = (entry.cspReportOnlyHeader() != null) ? entry.cspReportOnlyHeader() : "(not set)";
                    if (matchesText(ro, valueFilter)) list.add(entry);
                } else if (normalizedMode.equalsIgnoreCase("All Sources (Directives)")) {
                    if (entry.isMissingCsp()) {
                        if (matchesText("(missing CSP)", valueFilter)) list.add(entry);
                    } else {
                        boolean matched = false;
                        for (Map.Entry<String, List<String>> dir : entry.parsedDirectives().entrySet()) {
                            for (String token : dir.getValue()) {
                                if (matchesText(dir.getKey() + " " + token, valueFilter)) {
                                    matched = true;
                                    break;
                                }
                            }
                            if (matched) break;
                        }
                        if (matched) list.add(entry);
                    }
                } else {
                    if (matchesText(entry.getDirectiveString(normalizedMode), valueFilter)) list.add(entry);
                }
            }
        }

        return list;
    }

    private static boolean matchesText(String source, String filter) {
        if (filter == null || filter.trim().isEmpty()) return true;
        if (source == null) return false;
        return source.toLowerCase().contains(filter.trim().toLowerCase());
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
