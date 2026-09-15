// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Finding types ported directly from Google's CSP Evaluator (finding.ts:Type).
 *
 * @author littlespidy
 */
public enum CspFindingType {
    // Parser checks
    MISSING_SEMICOLON(100, "Missing Semicolon"),
    UNKNOWN_DIRECTIVE(101, "Unknown Directive"),
    INVALID_KEYWORD(102, "Invalid Keyword"),
    NONCE_CHARSET(106, "Invalid Nonce Charset"),

    // Security checks
    MISSING_DIRECTIVES(300, "Missing Directive"),
    SCRIPT_UNSAFE_INLINE(301, "'unsafe-inline' in Script"),
    SCRIPT_UNSAFE_EVAL(302, "'unsafe-eval' in Script"),
    PLAIN_URL_SCHEMES(303, "Plain URL Schemes"),
    PLAIN_WILDCARD(304, "Plain Wildcard"),
    SCRIPT_ALLOWLIST_BYPASS(305, "Script Allowlist Bypass (JSONP/Angular)"),
    OBJECT_ALLOWLIST_BYPASS(306, "Object Allowlist Bypass (Flash)"),
    NONCE_LENGTH(307, "Short Nonce Length"),
    IP_SOURCE(308, "IP Address Source"),
    DEPRECATED_DIRECTIVE(309, "Deprecated Directive"),
    SRC_HTTP(310, "HTTP Resource over Insecure Scheme"),
    SRC_NO_PROTOCOL(311, "Missing Protocol"),
    EXPERIMENTAL(312, "Experimental Directive"),
    WILDCARD_URL(313, "Wildcard Host in URL"),
    X_FRAME_OPTIONS_OBSOLETED(314, "X-Frame-Options Obsoleted by frame-ancestors"),
    STYLE_UNSAFE_INLINE(315, "'unsafe-inline' in Style"),
    STATIC_NONCE(316, "Static Nonce"),
    SCRIPT_UNSAFE_HASHES(317, "'unsafe-hashes' in Script"),

    // Strict dynamic and backward compatibility checks
    STRICT_DYNAMIC(400, "Missing 'strict-dynamic'"),
    STRICT_DYNAMIC_NOT_STANDALONE(401, "'strict-dynamic' without Nonce/Hash"),
    NONCE_HASH(402, "Nonce / Hash Finding"),
    UNSAFE_INLINE_FALLBACK(403, "Missing 'unsafe-inline' Fallback"),
    ALLOWLIST_FALLBACK(404, "Missing Allowlist Fallback"),
    IGNORED(405, "Ignored Entry"),

    // Trusted Types checks
    REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS(500, "Require Trusted Types"),

    // Reporting checks
    REPORTING_DESTINATION_MISSING(600, "Missing Reporting Destination"),
    REPORT_TO_ONLY(601, "Only report-to Configured");

    private final int code;
    private final String displayName;

    CspFindingType(int code, String displayName) {
        this.code = code;
        this.displayName = displayName;
    }

    public int getCode() {
        return code;
    }

    public String getDisplayName() {
        return displayName;
    }
}
