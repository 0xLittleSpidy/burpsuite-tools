// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Offline, dependency-free utility for parsing JWT claims and token metadata
 * from HTTP headers, specifically calculating character length and expiration (exp) validity.
 */
public final class JwtTokenHelper_littlespidy {

    private static final DateTimeFormatter UTC_FORMATTER = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss 'UTC'")
            .withZone(ZoneOffset.UTC);

    private JwtTokenHelper_littlespidy() {
    }

    public record JwtExpirationInfo(
            boolean hasToken,
            int tokenLength,
            int headerLength,
            boolean isJwt,
            Long expEpochSecond,
            boolean isExpired,
            String formattedRemainingTime,
            String formattedUtcTime,
            String summaryText
    ) {}

    /**
     * Parses the provided raw headers or token string to extract length and JWT expiration metadata.
     *
     * @param rawHeaders complete headers string or raw token
     * @return JwtExpirationInfo metadata record
     */
    public static JwtExpirationInfo parse(String rawHeaders) {
        if (rawHeaders == null || rawHeaders.isBlank()) {
            return new JwtExpirationInfo(false, 0, 0, false, null, false, "", "", "No token configured");
        }

        String authHeaderValue = extractAuthHeaderValue(rawHeaders);
        String token = extractBearerToken(authHeaderValue);

        if (token.isEmpty()) {
            return new JwtExpirationInfo(false, 0, 0, false, null, false, "", "", "No token found");
        }

        int tokenLen = token.length();
        int headerLen = authHeaderValue.length();

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return new JwtExpirationInfo(true, tokenLen, headerLen, false, null, false, "", "",
                    "Length: " + tokenLen + " chars (Non-JWT token)");
        }

        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);
            JsonElement element = JsonParser.parseString(payloadJson);
            if (!element.isJsonObject()) {
                return new JwtExpirationInfo(true, tokenLen, headerLen, true, null, false, "", "",
                        "Length: " + tokenLen + " chars (Invalid JWT payload)");
            }

            JsonObject obj = element.getAsJsonObject();
            if (obj.has("exp") && obj.get("exp").isJsonPrimitive()) {
                long expSec = obj.get("exp").getAsLong();
                long nowSec = Instant.now().getEpochSecond();
                long diff = expSec - nowSec;
                boolean expired = diff <= 0;

                String remainingStr = formatDuration(diff);
                String utcTimeStr = UTC_FORMATTER.format(Instant.ofEpochSecond(expSec));
                String summary = "Len: " + tokenLen + " chars | " + (expired ? "Expired: " + remainingStr : "Expires in: " + remainingStr);

                return new JwtExpirationInfo(true, tokenLen, headerLen, true, expSec, expired, remainingStr, utcTimeStr, summary);
            } else {
                return new JwtExpirationInfo(true, tokenLen, headerLen, true, null, false, "", "",
                        "Len: " + tokenLen + " chars (JWT has no exp claim)");
            }
        } catch (Exception ex) {
            return new JwtExpirationInfo(true, tokenLen, headerLen, false, null, false, "", "",
                    "Length: " + tokenLen + " chars (Non-JWT token)");
        }
    }

    /**
     * Extracts the Authorization header value if present, or returns the entire trimmed string.
     */
    public static String extractAuthHeaderValue(String rawHeaders) {
        if (rawHeaders == null || rawHeaders.isBlank()) {
            return "";
        }
        String[] lines = rawHeaders.split("[\\r\\n]+");
        boolean hasMultipleLines = lines.length > 1;
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String name = line.substring(0, colon).trim();
                if ("Authorization".equalsIgnoreCase(name)) {
                    return line.substring(colon + 1).trim();
                }
            }
        }
        // If multiple header lines exist but no Authorization header was found, return empty
        if (hasMultipleLines || rawHeaders.contains(":")) {
            return "";
        }
        // If single line input without headers, inspect if the string itself is a raw token
        String trimmed = rawHeaders.trim();
        if (trimmed.toLowerCase().startsWith("bearer ") || (trimmed.contains(".") && trimmed.split("\\.").length == 3)) {
            return trimmed;
        }
        return "";
    }

    /**
     * Strips "Bearer " prefix if present.
     */
    public static String extractBearerToken(String authHeaderValue) {
        if (authHeaderValue == null) {
            return "";
        }
        String trimmed = authHeaderValue.trim();
        if (trimmed.toLowerCase().startsWith("bearer ")) {
            return trimmed.substring(7).trim();
        }
        return trimmed;
    }

    /**
     * Formats time difference in seconds into human-readable duration string.
     */
    public static String formatDuration(long diffSeconds) {
        long absSeconds = Math.abs(diffSeconds);
        long days = absSeconds / 86400;
        long hours = (absSeconds % 86400) / 3600;
        long minutes = (absSeconds % 3600) / 60;
        long seconds = absSeconds % 60;

        StringBuilder sb = new StringBuilder();
        if (days > 0) {
            sb.append(days).append("d ");
        }
        if (hours > 0 || days > 0) {
            sb.append(hours).append("h ");
        }
        if (minutes > 0 || hours > 0 || days > 0) {
            sb.append(minutes).append("m ");
        }
        sb.append(seconds).append("s");
        return sb.toString().trim();
    }
}
