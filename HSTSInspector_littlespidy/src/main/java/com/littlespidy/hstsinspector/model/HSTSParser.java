// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.model;

/**
 * Stateless parser for the {@code Strict-Transport-Security} header value.
 *
 * <p>The RFC 6797 grammar is:
 * <pre>
 *   Strict-Transport-Security = "max-age" "=" delta-seconds
 *                               *( ";" directive-params )
 *   directive-params = "includeSubDomains" / "preload" / token [ "=" token ]
 * </pre>
 *
 * @author littlespidy
 */
public class HSTSParser {

    /** Sentinel value meaning the header was absent or unparseable. */
    public static final long MAX_AGE_MISSING = -1L;

    private HSTSParser() {}

    /**
     * Parses a raw {@code Strict-Transport-Security} header value.
     * Returns a {@link ParsedHSTS} result object.
     *
     * @param headerValue the raw header value; may be {@code null} or blank
     */
    public static ParsedHSTS parse(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return new ParsedHSTS(MAX_AGE_MISSING, false, false);
        }

        long maxAge = MAX_AGE_MISSING;
        boolean includeSubDomains = false;
        boolean preload = false;

        for (String token : headerValue.split(";")) {
            String directive = token.trim();
            if (directive.isEmpty()) continue;

            String lower = directive.toLowerCase();

            if (lower.startsWith("max-age")) {
                // Accept "max-age=N" or "max-age = N" (lenient)
                int eqIdx = directive.indexOf('=');
                if (eqIdx >= 0) {
                    String val = directive.substring(eqIdx + 1).trim();
                    try {
                        maxAge = Long.parseLong(val);
                        if (maxAge < 0) maxAge = 0; // clamp negative to 0
                    } catch (NumberFormatException ignored) {
                        // malformed; leave as MISSING
                    }
                }
            } else if (lower.equals("includesubdomains")) {
                includeSubDomains = true;
            } else if (lower.equals("preload")) {
                preload = true;
            }
            // Unknown directives are silently ignored per RFC 6797 §6.1
        }

        return new ParsedHSTS(maxAge, includeSubDomains, preload);
    }

    /**
     * Simple value-object holding the three parsed HSTS fields.
     */
    public record ParsedHSTS(long maxAge, boolean includeSubDomains, boolean preload) {}
}
