// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.util;

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

    public static class JwtExpirationInfo {
        private final boolean hasToken;
        private final int tokenLength;
        private final int headerLength;
        private final boolean isJwt;
        private final Long expEpochSecond;
        private final boolean isExpired;
        private final String formattedRemainingTime;
        private final String formattedUtcTime;
        private final String summaryText;

        public JwtExpirationInfo(boolean hasToken, int tokenLength, int headerLength, boolean isJwt,
                                 Long expEpochSecond, boolean isExpired, String formattedRemainingTime,
                                 String formattedUtcTime, String summaryText) {
            this.hasToken = hasToken;
            this.tokenLength = tokenLength;
            this.headerLength = headerLength;
            this.isJwt = isJwt;
            this.expEpochSecond = expEpochSecond;
            this.isExpired = isExpired;
            this.formattedRemainingTime = formattedRemainingTime;
            this.formattedUtcTime = formattedUtcTime;
            this.summaryText = summaryText;
        }

        public boolean hasToken() { return hasToken; }
        public int tokenLength() { return tokenLength; }
        public int headerLength() { return headerLength; }
        public boolean isJwt() { return isJwt; }
        public Long expEpochSecond() { return expEpochSecond; }
        public boolean isExpired() { return isExpired; }
        public String formattedRemainingTime() { return formattedRemainingTime; }
        public String formattedUtcTime() { return formattedUtcTime; }
        public String summaryText() { return summaryText; }
    }

    public static JwtExpirationInfo parse(String rawHeaders) {
        if (rawHeaders == null || rawHeaders.trim().isEmpty()) {
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

    public static String extractAuthHeaderValue(String rawHeaders) {
        if (rawHeaders == null || rawHeaders.trim().isEmpty()) {
            return "";
        }
        String[] lines = rawHeaders.split("\r?\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.regionMatches(true, 0, "Authorization:", 0, 14)) {
                return trimmed.substring(14).trim();
            }
        }
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.contains(":") && trimmed.length() > 20) {
                return trimmed;
            }
        }
        return rawHeaders.trim();
    }

    public static String extractBearerToken(String headerValue) {
        if (headerValue == null || headerValue.trim().isEmpty()) {
            return "";
        }
        String trimmed = headerValue.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return trimmed.substring(7).trim();
        }
        return trimmed;
    }

    public static String formatDuration(long diffSeconds) {
        long seconds = Math.abs(diffSeconds);
        long days = seconds / 86400;
        long rem1 = seconds % 86400;
        long hours = rem1 / 3600;
        long rem2 = rem1 % 3600;
        long mins = rem2 / 60;
        long secs = rem2 % 60;

        StringBuilder sb = new StringBuilder();
        if (days > 0) {
            sb.append(days).append("d ");
        }
        if (hours > 0 || days > 0) {
            sb.append(hours).append("h ");
        }
        if (mins > 0 || hours > 0 || days > 0) {
            sb.append(mins).append("m ");
        }
        sb.append(secs).append("s");

        if (diffSeconds < 0) {
            sb.append(" ago");
        }
        return sb.toString().trim();
    }
}
