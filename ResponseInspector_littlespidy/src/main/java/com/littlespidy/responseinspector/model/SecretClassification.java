// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

/**
 * Verification classifications for detected secrets.
 */
public enum SecretClassification {
    TRUE_POSITIVE("True Positive"),
    FALSE_POSITIVE("False Positive"),
    NOT_VERIFIED("Not Verified");

    private final String displayName;

    SecretClassification(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static SecretClassification fromDisplayName(String name) {
        if (name == null) {
            return NOT_VERIFIED;
        }
        for (SecretClassification sc : values()) {
            if (sc.displayName.equalsIgnoreCase(name.trim())) {
                return sc;
            }
        }
        return NOT_VERIFIED;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
