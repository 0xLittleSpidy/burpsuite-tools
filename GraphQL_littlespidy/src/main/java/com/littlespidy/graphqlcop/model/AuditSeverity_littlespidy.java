// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.model;

public enum AuditSeverity_littlespidy {
    HIGH("High"),
    MEDIUM("Medium"),
    LOW("Low"),
    INFO("Info");

    private final String label;

    AuditSeverity_littlespidy(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
