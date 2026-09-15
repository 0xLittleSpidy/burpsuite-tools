// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a security bypass method or dangerous DOM sink discovered in a
 * JavaScript file or unpacked Source Map source file.
 *
 * <p>Identifies framework-specific sanitization bypasses (Angular DomSanitizer,
 * React dangerouslySetInnerHTML, Vue v-html, Svelte @html), sanitizer misconfigurations
 * (DOMPurify, Trusted Types policies), and direct dangerous DOM sinks (innerHTML, eval).
 *
 * <p>Includes framework classification, method name, risk severity rating, line numbers,
 * and exact character offsets for 4-pillar deep-linking in Burp's editors.
 *
 * @author littlespidy
 */
public record DiscoveredSecurityBypass(
    String sourceLocation,
    String sourceType,
    String framework,       // "Angular", "React", "Vue", "Svelte", "Sanitizer / Policy Bypass", "Vanilla DOM Sink", "jQuery"
    String method,          // e.g. "bypassSecurityTrustHtml", "dangerouslySetInnerHTML", "v-html", "innerHTML assignment"
    String risk,            // "Critical", "High", "Medium"
    String confidence,      // "High [Firm]", "Medium", "Low [Tentative]"
    int line,
    int startOffset,
    int endOffset,
    String contextSnippet,
    String description
) {
    public DiscoveredSecurityBypass(
        String sourceLocation,
        String sourceType,
        String framework,
        String method,
        String risk,
        String confidence,
        int line,
        String contextSnippet,
        String description
    ) {
        this(sourceLocation, sourceType, framework, method, risk, confidence, line, 0, 0, contextSnippet, description);
    }
}
