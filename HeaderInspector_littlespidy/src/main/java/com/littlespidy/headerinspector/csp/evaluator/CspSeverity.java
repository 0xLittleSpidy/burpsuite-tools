// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import java.awt.Color;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Severity levels ported directly from Google's CSP Evaluator (finding.ts:Severity).
 *
 * @author littlespidy
 */
public enum CspSeverity {
    HIGH(10, "HIGH", new Color(211, 47, 47)),              // Red
    SYNTAX(20, "SYNTAX", new Color(230, 81, 0)),          // Deep Orange
    MEDIUM(30, "MEDIUM", new Color(245, 124, 0)),          // Orange
    HIGH_MAYBE(40, "HIGH?", new Color(251, 140, 0)),       // Amber-Orange
    STRICT_CSP(45, "STRICT CSP", new Color(123, 31, 162)), // Purple
    MEDIUM_MAYBE(50, "MEDIUM?", new Color(255, 160, 0)),   // Amber
    INFO(60, "INFO", new Color(25, 118, 210)),             // Blue
    NONE(100, "PASS", new Color(56, 142, 60));             // Green

    private final int rank;
    private final String label;
    private final Color color;

    CspSeverity(int rank, String label, Color color) {
        this.rank = rank;
        this.label = label;
        this.color = color;
    }

    public int getRank() {
        return rank;
    }

    public String getLabel() {
        return label;
    }

    public Color getColor() {
        return color;
    }

    public static CspSeverity getHighest(Iterable<CspFinding> findings) {
        CspSeverity highest = NONE;
        for (CspFinding f : findings) {
            if (f.severity().getRank() < highest.getRank()) {
                highest = f.severity();
            }
        }
        return highest;
    }
}
