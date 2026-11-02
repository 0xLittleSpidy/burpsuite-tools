// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Holds a grouped finding representation containing a primary item and all duplicate occurrences.
 *
 * @param <T> Finding domain type (DiscoveredSecret, DiscoveredEndpoint, DiscoveredComment, etc.)
 * @author littlespidy
 */
public class GroupedFinding_littlespidy<T> {
    private T primary;
    private final List<T> occurrences = new ArrayList<>();
    private final List<FindingOccurrence_littlespidy> navOccurrences = new ArrayList<>();

    public GroupedFinding_littlespidy(T primary, FindingOccurrence_littlespidy initialOccurrence) {
        this.primary = primary;
        this.occurrences.add(primary);
        if (initialOccurrence != null) {
            this.navOccurrences.add(initialOccurrence);
        }
    }

    public synchronized void addOccurrence(T item, FindingOccurrence_littlespidy occ) {
        this.occurrences.add(item);
        if (occ != null) {
            this.navOccurrences.add(occ);
        }
    }

    public synchronized T getPrimary() {
        return primary;
    }

    public synchronized void setPrimary(T primary) {
        this.primary = primary;
    }

    public synchronized List<T> getOccurrences() {
        return Collections.unmodifiableList(occurrences);
    }

    public synchronized List<FindingOccurrence_littlespidy> getNavOccurrences() {
        return Collections.unmodifiableList(navOccurrences);
    }

    public synchronized int getCount() {
        return occurrences.size();
    }
}
