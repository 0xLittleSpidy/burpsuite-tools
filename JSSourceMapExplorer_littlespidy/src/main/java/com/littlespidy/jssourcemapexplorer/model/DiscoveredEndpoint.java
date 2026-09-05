// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents an API route, GraphQL query, or endpoint URL discovered in
 * either a raw JavaScript file or an unpacked Source Map source file.
 *
 * <p>The {@code technique} field describes the detection method (e.g.
 * {@code "HTTP Verb Call"}, {@code "API Namespace"}, {@code "Relative Path"},
 * {@code "Absolute URL"}, {@code "REST Endpoint"}, {@code "File Extension"}).
 *
 * @author littlespidy
 */
public record DiscoveredEndpoint(
    String sourceLocation,
    String sourceType,
    String endpoint,
    String methodGuess,
    int line,
    String contextSnippet,
    String technique
) {
    public String extractor() {
        return technique;
    }
}
