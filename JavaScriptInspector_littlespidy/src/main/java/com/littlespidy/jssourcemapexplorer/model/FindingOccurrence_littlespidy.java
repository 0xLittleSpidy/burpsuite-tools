// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a single concrete occurrence of a finding in a specific file and offset.
 * Used for occurrence navigation [1] [2] [3]... when duplicate findings are grouped.
 *
 * @author littlespidy
 */
public record FindingOccurrence_littlespidy(
    String sourceLocation,
    String sourceType,
    String findingText,
    int line,
    int startOffset,
    int endOffset,
    String contextSnippet
) {}
