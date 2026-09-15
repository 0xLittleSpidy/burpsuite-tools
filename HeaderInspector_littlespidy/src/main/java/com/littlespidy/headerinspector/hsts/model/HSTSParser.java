// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.hsts.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Stateless parser for the Strict-Transport-Security header value.
 *
 * @author littlespidy
 */
public class HSTSParser {

    public static final long MAX_AGE_MISSING = -1L;

    private HSTSParser() {}

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
                int eqIdx = directive.indexOf('=');
                if (eqIdx >= 0) {
                    String val = directive.substring(eqIdx + 1).trim();
                    try {
                        maxAge = Long.parseLong(val);
                        if (maxAge < 0) maxAge = 0;
                    } catch (NumberFormatException ignored) {}
                }
            } else if (lower.equals("includesubdomains")) {
                includeSubDomains = true;
            } else if (lower.equals("preload")) {
                preload = true;
            }
        }

        return new ParsedHSTS(maxAge, includeSubDomains, preload);
    }

    public record ParsedHSTS(long maxAge, boolean includeSubDomains, boolean preload) {}
}
