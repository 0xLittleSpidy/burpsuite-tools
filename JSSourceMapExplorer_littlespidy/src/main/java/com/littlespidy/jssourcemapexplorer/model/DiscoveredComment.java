// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a developer comment (single-line, multi-line, or HTML style)
 * discovered in a JavaScript file or unpacked Source Map source file.
 *
 * <p>Includes comment category (TODO/FIXME, Credentials/Auth, Debug/Config, General),
 * line numbers, and character offsets for 4-pillar deep-linking in Burp editors.
 *
 * @author littlespidy
 */
public record DiscoveredComment(
    String sourceLocation,
    String sourceType,
    String commentType,    // "Single-Line (//)", "Multi-Line (/* */)", "HTML (<!-- -->)"
    String category,       // "TODO / FIXME", "Credentials / Auth", "Debug / Config", "General"
    String commentText,
    int line,
    int startOffset,
    int endOffset,
    String contextSnippet
) {
    public DiscoveredComment(
        String sourceLocation,
        String sourceType,
        String commentType,
        String category,
        String commentText,
        int line,
        String contextSnippet
    ) {
        this(sourceLocation, sourceType, commentType, category, commentText, line, 0, 0, contextSnippet);
    }
}
