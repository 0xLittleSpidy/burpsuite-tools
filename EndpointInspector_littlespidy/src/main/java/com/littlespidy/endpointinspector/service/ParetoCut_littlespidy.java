// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Pareto-cut ranking implementation ported from reKover.
 * Retains the 'vital few' from weighted endpoints, walking the ranking until
 * cumulative weight reaches 80% of the total, hard-capped at a ceiling.
 *
 * @author littlespidy
 */
public final class ParetoCut_littlespidy {

    private ParetoCut_littlespidy() {}

    public record WeightedItem<T>(long weight, T item) {}

    public static <T> List<T> cut(List<WeightedItem<T>> items, int hardCap, double thresholdRatio) {
        if (items == null || items.isEmpty() || hardCap <= 0) {
            return Collections.emptyList();
        }

        List<WeightedItem<T>> sorted = new ArrayList<>(items);
        sorted.sort(Comparator.<WeightedItem<T>>comparingLong(WeightedItem::weight).reversed());

        long totalWeight = 0;
        for (WeightedItem<T> wi : sorted) {
            totalWeight += wi.weight();
        }

        double threshold = totalWeight * thresholdRatio;
        long accumulated = 0;
        List<T> result = new ArrayList<>();

        for (WeightedItem<T> wi : sorted) {
            if (result.size() >= hardCap) break;
            result.add(wi.item());
            accumulated += wi.weight();
            if (accumulated >= threshold) break;
        }

        return result;
    }

    public static <T> List<T> cut(List<WeightedItem<T>> items, int hardCap) {
        return cut(items, hardCap, 0.80);
    }
}
