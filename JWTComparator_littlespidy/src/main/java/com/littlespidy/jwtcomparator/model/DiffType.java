// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

/**
 * Represents the diff status of a claim key across compared JWT tokens.
 */
public enum DiffType {
    IDENTICAL("Identical", "Equal across all tokens"),
    MISMATCH("Value Mismatch", "Values differ between tokens"),
    PARTIAL_ABSENT("Partially Missing", "Claim absent in one or more tokens");

    private final String displayName;
    private final String description;

    DiffType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
