// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.knowledge;

import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable record representing an HTTP status code's complete documentation,
 * class, meaning, recommended client actions, and RFC specifications from https://http.dev.
 *
 * @author littlespidy
 */
public record HttpDevStatusDoc(
    int code,
    String name,
    String slug,
    String statusClass,
    String meaning,
    String clientAction,
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
