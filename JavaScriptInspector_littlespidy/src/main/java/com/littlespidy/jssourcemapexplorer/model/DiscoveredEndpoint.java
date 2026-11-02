// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents an API route, GraphQL query, or endpoint URL discovered in
 * either a raw JavaScript file or an unpacked Source Map source file.
 *
 * <p>Includes start and end character offsets for deep-linking quad navigation.
 *
 * @author littlespidy
 */
public record DiscoveredEndpoint(
    String sourceLocation,
    String sourceType,
    String endpoint,
    String methodGuess,
    int line,
    int startOffset,
    int endOffset,
    String contextSnippet,
    String technique,
    String classification
) {
    public DiscoveredEndpoint {
        if (classification == null || classification.isBlank()) {
            classification = "Not Classified";
        }
    }

    public DiscoveredEndpoint(
        String sourceLocation,
        String sourceType,
        String endpoint,
        String methodGuess,
        int line,
        int startOffset,
        int endOffset,
        String contextSnippet,
        String technique
    ) {
        this(sourceLocation, sourceType, endpoint, methodGuess, line, startOffset, endOffset, contextSnippet, technique, "Not Classified");
    }

    public DiscoveredEndpoint(
        String sourceLocation,
        String sourceType,
        String endpoint,
        String methodGuess,
        int line,
        String contextSnippet,
        String technique
    ) {
        this(sourceLocation, sourceType, endpoint, methodGuess, line, 0, 0, contextSnippet, technique, "Not Classified");
    }

    public DiscoveredEndpoint withClassification(String newClassification) {
        return new DiscoveredEndpoint(
            sourceLocation,
            sourceType,
            endpoint,
            methodGuess,
            line,
            startOffset,
            endOffset,
            contextSnippet,
            technique,
            newClassification
        );
    }

    public String extractor() {
        return technique;
    }
}
