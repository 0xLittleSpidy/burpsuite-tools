// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.model;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Thread-safe central in-memory store for session expiration tasks.
 *
 * @author littlespidy
 */
public class SessionDataStore {

    private final List<SessionTask> allTasks = new CopyOnWriteArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(1);
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public int nextId() {
        return idCounter.getAndIncrement();
    }

    public void addTask(SessionTask task) {
        allTasks.add(task);
        notifyListeners();
    }

    public void removeTask(int taskId) {
        allTasks.removeIf(t -> t.getId() == taskId);
        notifyListeners();
    }

    public void clearAll() {
        for (SessionTask task : allTasks) {
            task.cancelRemainingFutures();
        }
        allTasks.clear();
        notifyListeners();
    }

    public List<SessionTask> getAllTasks() {
        return Collections.unmodifiableList(allTasks);
    }

    public SessionTask getTaskById(int id) {
        for (SessionTask t : allTasks) {
            if (t.getId() == id) {
                return t;
            }
        }
        return null;
    }

    public void addChangeListener(Runnable r) {
        listeners.add(r);
    }

    public void removeChangeListener(Runnable r) {
        listeners.remove(r);
    }

    public void notifyListeners() {
        for (Runnable r : listeners) {
            try {
                r.run();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Filters tasks based on domain, HTTP methods, status code string, and session state.
     */
    public List<SessionTask> getFilteredTasks(
            String domainFilter,
            Set<String> selectedMethods,
            String statusFilter,
            String stateFilter
    ) {
        return allTasks.stream()
                .filter(t -> matchesDomain(t.getHost(), domainFilter))
                .filter(t -> matchesMethod(t.getMethod(), selectedMethods))
                .filter(t -> matchesStatus(t.getBaselineStatusCode(), statusFilter))
                .filter(t -> matchesState(t.getState(), stateFilter))
                .collect(Collectors.toList());
    }

    public static boolean matchesDomain(String entryHost, String domainFilter) {
        if (domainFilter == null || domainFilter.trim().isEmpty() || domainFilter.equalsIgnoreCase("All")) {
            return true;
        }
        if (entryHost == null) return false;

        String cleanFilter = domainFilter.trim().toLowerCase(Locale.ROOT);
        if (cleanFilter.startsWith("http://")) cleanFilter = cleanFilter.substring(7);
        if (cleanFilter.startsWith("https://")) cleanFilter = cleanFilter.substring(8);
        int slashIdx = cleanFilter.indexOf('/');
        if (slashIdx != -1) cleanFilter = cleanFilter.substring(0, slashIdx);
        int colonIdx = cleanFilter.indexOf(':');
        if (colonIdx != -1) cleanFilter = cleanFilter.substring(0, colonIdx);
        if (cleanFilter.startsWith("*.")) cleanFilter = cleanFilter.substring(2);

        String host = entryHost.toLowerCase(Locale.ROOT);
        int hostColon = host.indexOf(':');
        if (hostColon != -1) host = host.substring(0, hostColon);

        return host.equalsIgnoreCase(cleanFilter)
                || host.endsWith("." + cleanFilter)
                || host.contains(cleanFilter);
    }

    public static boolean matchesMethod(String method, Set<String> selectedMethods) {
        if (selectedMethods == null || selectedMethods.isEmpty() || selectedMethods.contains("All Methods")) {
            return true;
        }
        if (method == null) return false;
        return selectedMethods.contains(method.toUpperCase(Locale.ROOT));
    }

    public static boolean matchesStatus(int statusCode, String filter) {
        if (filter == null || filter.trim().isEmpty() || filter.equalsIgnoreCase("All") || filter.equalsIgnoreCase("All Statuses")) {
            return true;
        }
        if (statusCode <= 0) return false;

        String[] tokens = filter.split("[,/\\s]+");
        for (String rawToken : tokens) {
            String token = rawToken.trim();
            if (token.isEmpty()) continue;

            if (token.equalsIgnoreCase("2xx") && statusCode >= 200 && statusCode < 300) return true;
            if (token.equalsIgnoreCase("3xx") && statusCode >= 300 && statusCode < 400) return true;
            if (token.equalsIgnoreCase("4xx") && statusCode >= 400 && statusCode < 500) return true;
            if (token.equalsIgnoreCase("5xx") && statusCode >= 500 && statusCode < 600) return true;

            try {
                int targetCode = Integer.parseInt(token);
                if (statusCode == targetCode) return true;
            } catch (NumberFormatException ignored) {
            }
        }
        return false;
    }

    public static boolean matchesState(SessionState state, String stateFilter) {
        if (stateFilter == null || stateFilter.trim().isEmpty() || stateFilter.equalsIgnoreCase("All") || stateFilter.equalsIgnoreCase("All States")) {
            return true;
        }
        if (state == null) return false;
        return state.name().equalsIgnoreCase(stateFilter.trim())
                || state.getDisplayName().equalsIgnoreCase(stateFilter.trim());
    }
}
