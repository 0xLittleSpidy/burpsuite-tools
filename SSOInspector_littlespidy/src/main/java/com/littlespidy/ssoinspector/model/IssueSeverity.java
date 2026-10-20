// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.model;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public enum IssueSeverity {
    HIGH("High", 4),
    MEDIUM("Medium", 3),
    LOW("Low", 2),
    INFORMATION("Information", 1),
    CLEAN("Clean", 0);

    private final String label;
    private final int rank;

    IssueSeverity(String label, int rank) {
        this.label = label;
        this.rank = rank;
    }

    public String getLabel() {
        return label;
    }

    public int getRank() {
        return rank;
    }

    public AuditIssueSeverity toMontoyaSeverity() {
        return switch (this) {
            case HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case LOW -> AuditIssueSeverity.LOW;
            case INFORMATION, CLEAN -> AuditIssueSeverity.INFORMATION;
        };
    }

    public static IssueSeverity fromString(String text) {
        if (text == null) return INFORMATION;
        for (IssueSeverity s : values()) {
            if (s.name().equalsIgnoreCase(text) || s.label.equalsIgnoreCase(text)) {
                return s;
            }
        }
        return INFORMATION;
    }
}
