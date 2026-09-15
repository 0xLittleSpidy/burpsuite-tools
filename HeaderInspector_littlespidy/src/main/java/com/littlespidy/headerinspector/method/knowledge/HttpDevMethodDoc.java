// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.knowledge;

import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable record representing an HTTP method's complete documentation,
 * properties (Safe, Idempotent, Cacheable), and specifications from https://http.dev.
 *
 * @author littlespidy
 */
public record HttpDevMethodDoc(
    String name,
    String slug,
    boolean safe,
    boolean idempotent,
    String cacheable,
    String summary,
    String explanation,
    String referenceUrl,
    List<Specification> specifications
) {

    /**
     * Specification reference (e.g. RFC or standard document)
     */
    public record Specification(String title, String url) {}

    public boolean hasSpecifications() {
        return specifications != null && !specifications.isEmpty();
    }
}
