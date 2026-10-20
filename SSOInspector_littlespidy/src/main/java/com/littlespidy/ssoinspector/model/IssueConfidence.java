// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.model;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

public enum IssueConfidence {
    CERTAIN("Certain"),
    FIRM("Firm"),
    TENTATIVE("Tentative");

    private final String label;

    IssueConfidence(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public AuditIssueConfidence toMontoyaConfidence() {
        return switch (this) {
            case CERTAIN -> AuditIssueConfidence.CERTAIN;
            case FIRM -> AuditIssueConfidence.FIRM;
            case TENTATIVE -> AuditIssueConfidence.TENTATIVE;
        };
    }

    public static IssueConfidence fromString(String text) {
        if (text == null) return TENTATIVE;
        for (IssueConfidence c : values()) {
            if (c.name().equalsIgnoreCase(text) || c.label.equalsIgnoreCase(text)) {
                return c;
            }
        }
        return TENTATIVE;
    }
}
