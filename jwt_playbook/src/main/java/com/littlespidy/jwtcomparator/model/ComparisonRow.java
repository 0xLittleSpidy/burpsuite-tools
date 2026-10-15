// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

import java.util.*;

/**
 * Represents a single row in the claims comparison matrix.
 */
public class ComparisonRow {
    private final String section; // "Header" or "Payload"
    private final String claimKey;
    private final Map<Integer, Object> rawValues;
    private final Map<Integer, String> formattedValues;
    private final DiffType diffType;
    private final boolean isTimestamp;

    public ComparisonRow(String section, String claimKey, Map<Integer, Object> rawValues,
                         Map<Integer, String> formattedValues, DiffType diffType, boolean isTimestamp) {
        this.section = section;
        this.claimKey = claimKey;
        this.rawValues = rawValues;
        this.formattedValues = formattedValues;
        this.diffType = diffType;
        this.isTimestamp = isTimestamp;
    }

    public String getSection() {
        return section;
    }

    public String getClaimKey() {
        return claimKey;
    }

    public Object getRawValue(int slotIndex) {
        return rawValues.get(slotIndex);
    }

    public boolean hasValue(int slotIndex) {
        return rawValues.containsKey(slotIndex);
    }

    public String getFormattedValue(int slotIndex) {
        return formattedValues.getOrDefault(slotIndex, "[MISSING]");
    }

    public DiffType getDiffType() {
        return diffType;
    }

    public boolean isTimestamp() {
        return isTimestamp;
    }

    public boolean isDifference() {
        return diffType != DiffType.IDENTICAL;
    }

    public boolean matchesSearch(String query) {
        if (query == null || query.trim().isEmpty()) {
            return true;
        }
        String lower = query.trim().toLowerCase();
        if (claimKey.toLowerCase().contains(lower) || section.toLowerCase().contains(lower)) {
            return true;
        }
        for (String val : formattedValues.values()) {
            if (val != null && val.toLowerCase().contains(lower)) {
                return true;
            }
        }
        return false;
    }
}
