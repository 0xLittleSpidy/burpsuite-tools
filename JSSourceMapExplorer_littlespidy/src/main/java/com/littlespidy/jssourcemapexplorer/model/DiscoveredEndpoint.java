// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents an API route, GraphQL query, or endpoint URL discovered in
 * either a raw JavaScript file or an unpacked Source Map source file.
 *
 * @author littlespidy
 */
public record DiscoveredEndpoint(
    String sourceLocation,
    String sourceType,
    String endpoint,
    String methodGuess,
    int line,
    String contextSnippet
) {}
