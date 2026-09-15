// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.knowledge;

import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable record representing an HTTP header's complete documentation
 * and specifications scraped from https://http.dev.
 *
 * @author littlespidy
 */
public record HttpDevHeaderDoc(
    String name,
    String slug,
    String category,
    String summary,
    String explanation,
    String directives,
    String referenceUrl,
    List<Specification> specifications
) {

    /**
     * Specification reference (e.g. RFC or W3C document)
     */
    public record Specification(String title, String url) {}

    public boolean hasDirectives() {
        return directives != null && !directives.isBlank();
    }

    public boolean hasSpecifications() {
        return specifications != null && !specifications.isEmpty();
    }
}
