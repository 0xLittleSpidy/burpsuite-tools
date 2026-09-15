// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import java.util.Objects;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable record representing a single security or syntax finding from Google's CSP Evaluator.
 *
 * @author littlespidy
 */
public record CspFinding(
    CspFindingType type,
    String description,
    CspSeverity severity,
    String directive,
    String value
) implements Comparable<CspFinding> {

    public CspFinding {
        Objects.requireNonNull(type, "Finding type cannot be null");
        Objects.requireNonNull(severity, "Severity cannot be null");
        description = (description == null) ? "" : description;
        directive = (directive == null) ? "" : directive;
        value = (value == null) ? "" : value;
    }

    @Override
    public int compareTo(CspFinding other) {
        if (other == null) return 1;
        int sev = Integer.compare(this.severity.getRank(), other.severity.getRank());
        if (sev != 0) return sev;
        int dir = this.directive.compareToIgnoreCase(other.directive);
        if (dir != 0) return dir;
        return this.type.name().compareTo(other.type.name());
    }

    public String getDisplayTitle() {
        return type.getDisplayName();
    }
}
