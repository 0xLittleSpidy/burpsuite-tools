// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages discovered in-scope domains and user-selected domain filters.
 */
public class InScopeDomainManager {

    private final Set<String> allInScopeDomains = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    private final Set<String> selectedDomains = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    private final Map<String, Integer> domainFindingCounts = new ConcurrentHashMap<>();
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    public InScopeDomainManager() {}

    public synchronized void addDomain(String host) {
        if (host == null || host.isBlank()) return;
        String clean = host.trim().toLowerCase();
        boolean isNew = allInScopeDomains.add(clean);
        // By default, newly discovered in-scope domains are selected
        if (isNew) {
            selectedDomains.add(clean);
            notifyListeners();
        }
    }

    public synchronized void registerFinding(String host) {
        if (host == null || host.isBlank()) return;
        String clean = host.trim().toLowerCase();
        domainFindingCounts.merge(clean, 1, Integer::sum);
        addDomain(clean);
    }

    public synchronized int getFindingCount(String host) {
        if (host == null) return 0;
        return domainFindingCounts.getOrDefault(host.trim().toLowerCase(), 0);
    }

    public synchronized Set<String> getAllDomains() {
        return new TreeSet<>(allInScopeDomains);
    }

    public synchronized Set<String> getSelectedDomains() {
        return new TreeSet<>(selectedDomains);
    }

    public synchronized void setSelectedDomains(Collection<String> domains) {
        selectedDomains.clear();
        if (domains != null) {
            for (String d : domains) {
                if (d != null && !d.isBlank()) {
                    selectedDomains.add(d.trim().toLowerCase());
                }
            }
        }
        notifyListeners();
    }

    public synchronized void selectAll() {
        selectedDomains.clear();
        selectedDomains.addAll(allInScopeDomains);
        notifyListeners();
    }

    public synchronized void deselectAll() {
        selectedDomains.clear();
        notifyListeners();
    }

    public synchronized boolean isAllSelected() {
        return allInScopeDomains.isEmpty() || selectedDomains.size() >= allInScopeDomains.size();
    }

    public synchronized boolean isDomainSelected(String host) {
        if (host == null) return false;
        String clean = host.trim().toLowerCase();
        if (isAllSelected()) return true;
        return selectedDomains.contains(clean);
    }

    /**
     * Determines whether an entry with the given host matches the active domain selection.
     */
    public synchronized boolean matchesDomain(String host) {
        if (host == null || host.isBlank()) return true;
        if (allInScopeDomains.isEmpty()) return true;
        if (isAllSelected()) return true;
        String clean = host.trim().toLowerCase();
        if (selectedDomains.contains(clean)) return true;
        // Check subdomain matching if host is a subdomain of a selected domain
        for (String selected : selectedDomains) {
            if (clean.endsWith("." + selected)) {
                return true;
            }
        }
        return false;
    }

    public synchronized int getTotalDomainCount() {
        return allInScopeDomains.size();
    }

    public synchronized int getSelectedDomainCount() {
        return selectedDomains.size();
    }

    public void addChangeListener(Runnable listener) {
        if (listener != null) {
            changeListeners.add(listener);
        }
    }

    private void notifyListeners() {
        for (Runnable r : changeListeners) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }
}
