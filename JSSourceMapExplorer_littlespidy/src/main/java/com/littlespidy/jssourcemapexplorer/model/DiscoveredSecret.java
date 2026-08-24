// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a hardcoded secret, token, or sensitive credential discovered in
 * either a raw JavaScript file or an unpacked Source Map source file.
 *
 * @author littlespidy
 */
public record DiscoveredSecret(
    String sourceLocation,
    String sourceType,
    String category,
    String secretValue,
    int line,
    String contextSnippet
) {}
