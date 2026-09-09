// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Model representing a single JWT token slot in the comparator.
 */
public class JWTTokenModel {
    private static final DateTimeFormatter UTC_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter LOCAL_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final int slotIndex;
    private String label;
    private String rawToken;
    private boolean valid;
    private String parseError;

    private String rawHeader;
    private String rawPayload;
    private String signature;

    private String prettyHeaderJson;
    private String prettyPayloadJson;

    private Map<String, Object> headerClaims = new LinkedHashMap<>();
    private Map<String, Object> payloadClaims = new LinkedHashMap<>();

    public JWTTokenModel(int slotIndex, String defaultLabel) {
        this.slotIndex = slotIndex;
        this.label = defaultLabel;
        this.rawToken = "";
        this.valid = false;
        this.parseError = "No token provided";
    }

    public int getSlotIndex() {
        return slotIndex;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = (label != null && !label.trim().isEmpty()) ? label.trim() : "Token " + slotIndex;
    }

    public String getRawToken() {
        return rawToken;
    }

    public void setRawToken(String rawToken) {
        this.rawToken = (rawToken != null) ? rawToken.trim() : "";
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getParseError() {
        return parseError;
    }

    public void setParseError(String parseError) {
        this.parseError = parseError;
    }

    public String getRawHeader() {
        return rawHeader;
    }

    public void setRawHeader(String rawHeader) {
        this.rawHeader = rawHeader;
    }

    public String getRawPayload() {
        return rawPayload;
    }

    public void setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getPrettyHeaderJson() {
        return prettyHeaderJson != null ? prettyHeaderJson : "";
    }

    public void setPrettyHeaderJson(String prettyHeaderJson) {
        this.prettyHeaderJson = prettyHeaderJson;
    }

    public String getPrettyPayloadJson() {
        return prettyPayloadJson != null ? prettyPayloadJson : "";
    }

    public void setPrettyPayloadJson(String prettyPayloadJson) {
        this.prettyPayloadJson = prettyPayloadJson;
    }

    public Map<String, Object> getHeaderClaims() {
        return Collections.unmodifiableMap(headerClaims);
    }

    public void setHeaderClaims(Map<String, Object> headerClaims) {
        this.headerClaims = (headerClaims != null) ? new LinkedHashMap<>(headerClaims) : new LinkedHashMap<>();
    }

    public Map<String, Object> getPayloadClaims() {
        return Collections.unmodifiableMap(payloadClaims);
    }

    public void setPayloadClaims(Map<String, Object> payloadClaims) {
        this.payloadClaims = (payloadClaims != null) ? new LinkedHashMap<>(payloadClaims) : new LinkedHashMap<>();
    }

    public boolean hasClaim(String section, String key) {
        if ("Header".equalsIgnoreCase(section)) {
            return headerClaims.containsKey(key);
        } else {
            return payloadClaims.containsKey(key);
        }
    }

    public Object getClaim(String section, String key) {
        if ("Header".equalsIgnoreCase(section)) {
            return headerClaims.get(key);
        } else {
            return payloadClaims.get(key);
        }
    }

    public String getAlgorithm() {
        Object alg = headerClaims.get("alg");
        return alg != null ? String.valueOf(alg) : (valid ? "none" : "-");
    }

    public String getIssuer() {
        Object iss = payloadClaims.get("iss");
        return iss != null ? String.valueOf(iss) : "-";
    }

    public String getSubject() {
        Object sub = payloadClaims.get("sub");
        return sub != null ? String.valueOf(sub) : "-";
    }

    public String getAudience() {
        Object aud = payloadClaims.get("aud");
        return aud != null ? String.valueOf(aud) : "-";
    }

    /**
     * Translates standard epoch timestamp claims (exp, iat, nbf, auth_time) into human-readable strings.
     */
    public String getTimestampHumanReadable(String key) {
        Object val = payloadClaims.get(key);
        if (val == null) {
            return null;
        }

        try {
            long epochSec;
            if (val instanceof Number) {
                epochSec = ((Number) val).longValue();
            } else {
                epochSec = Long.parseLong(val.toString().trim());
            }

            Instant instant = Instant.ofEpochSecond(epochSec);
            String utcStr = UTC_FORMATTER.format(instant);
            String localStr = LOCAL_FORMATTER.format(instant);

            long nowSec = Instant.now().getEpochSecond();
            long diff = epochSec - nowSec;

            String relative;
            if ("exp".equalsIgnoreCase(key)) {
                if (diff < 0) {
                    relative = "Expired " + formatDuration(Math.abs(diff)) + " ago";
                } else {
                    relative = "Active (expires in " + formatDuration(diff) + ")";
                }
            } else if ("iat".equalsIgnoreCase(key) || "auth_time".equalsIgnoreCase(key)) {
                if (diff < 0) {
                    relative = "Issued " + formatDuration(Math.abs(diff)) + " ago";
                } else {
                    relative = "In future (" + formatDuration(diff) + ")";
                }
            } else if ("nbf".equalsIgnoreCase(key)) {
                if (diff < 0) {
                    relative = "Valid (started " + formatDuration(Math.abs(diff)) + " ago)";
                } else {
                    relative = "Not yet valid (in " + formatDuration(diff) + ")";
                }
            } else {
                relative = (diff < 0) ? formatDuration(Math.abs(diff)) + " ago" : "in " + formatDuration(diff);
            }

            return String.format("%d [%s / Local: %s] (%s)", epochSec, utcStr, localStr, relative);
        } catch (Exception e) {
            return String.valueOf(val);
        }
    }

    private static String formatDuration(long seconds) {
        if (seconds < 60) {
            return seconds + "s";
        }
        long minutes = seconds / 60;
        if (minutes < 60) {
            long sec = seconds % 60;
            return minutes + "m " + sec + "s";
        }
        long hours = minutes / 60;
        if (hours < 24) {
            long min = minutes % 60;
            return hours + "h " + min + "m";
        }
        long days = hours / 24;
        long hr = hours % 24;
        return days + "d " + hr + "h";
    }

    public void clear() {
        this.rawToken = "";
        this.valid = false;
        this.parseError = "No token provided";
        this.rawHeader = null;
        this.rawPayload = null;
        this.signature = null;
        this.prettyHeaderJson = null;
        this.prettyPayloadJson = null;
        this.headerClaims.clear();
        this.payloadClaims.clear();
    }
}
