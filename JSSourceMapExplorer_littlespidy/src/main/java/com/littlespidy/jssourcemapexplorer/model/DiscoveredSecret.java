// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a hardcoded secret, token, or sensitive credential discovered in
 * either a raw JavaScript file or an unpacked Source Map source file.
 *
 * <p>Includes Shannon entropy scoring and confidence classification.
 *
 * @author littlespidy
 */
public record DiscoveredSecret(
    String sourceLocation,
    String sourceType,
    String category,
    String secretValue,
    double entropy,
    String confidence,      // "High [Firm]" | "Low [Tentative]"
    String technique,       // "Pattern Signature" | "Variable Entropy Scan" | "HTTP Basic Auth"
    int line,
    String contextSnippet
) {}
