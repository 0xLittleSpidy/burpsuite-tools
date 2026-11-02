// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a hardcoded secret, token, or sensitive credential discovered in
 * either a raw JavaScript file or an unpacked Source Map source file.
 *
 * <p>Includes severity rating, Shannon entropy scoring, confidence classification,
 * and exact character offsets for 4-pillar deep-linking in Burp's editors.
 *
 * @author littlespidy
 */
public record DiscoveredSecret(
    String sourceLocation,
    String sourceType,
    String category,
    String secretValue,
    String severity,        // "Critical" | "High" | "Medium" | "Low" | "Info"
    double entropy,
    String confidence,      // "High [Firm]" | "Low [Tentative]"
    String technique,       // e.g. "GhostJS Curated", "Variable Entropy Scan", "HTTP Basic Auth"
    int line,
    int startOffset,
    int endOffset,
    String contextSnippet,
    String classification
) {
    public DiscoveredSecret {
        if (classification == null || classification.isBlank()) {
            classification = "Not Classified";
        }
    }

    public DiscoveredSecret(
        String sourceLocation,
        String sourceType,
        String category,
        String secretValue,
        String severity,
        double entropy,
        String confidence,
        String technique,
        int line,
        int startOffset,
        int endOffset,
        String contextSnippet
    ) {
        this(sourceLocation, sourceType, category, secretValue, severity, entropy, confidence, technique, line, startOffset, endOffset, contextSnippet, "Not Classified");
    }

    public DiscoveredSecret(
        String sourceLocation,
        String sourceType,
        String category,
        String secretValue,
        double entropy,
        String confidence,
        String technique,
        int line,
        String contextSnippet
    ) {
        this(sourceLocation, sourceType, category, secretValue, "High", entropy, confidence, technique, line, 0, 0, contextSnippet, "Not Classified");
    }

    public DiscoveredSecret withClassification(String newClassification) {
        return new DiscoveredSecret(
            sourceLocation,
            sourceType,
            category,
            secretValue,
            severity,
            entropy,
            confidence,
            technique,
            line,
            startOffset,
            endOffset,
            contextSnippet,
            newClassification
        );
    }
}
