// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

import com.google.gson.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-performance parser and extractor for JSON Web Tokens (JWT).
 */
public class JWTParser {

    private static final Pattern JWT_REGEX =
            Pattern.compile("\\beyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_\\-\\./+=]*\\b");

    private static final Pattern BEARER_REGEX =
            Pattern.compile("(?i)\\bBearer\\s+([a-zA-Z0-9_\\-\\.]+)");

    private static final Gson PRETTY_GSON = new GsonBuilder()
            .setPrettyPrinting()
            .serializeNulls()
            .disableHtmlEscaping()
            .create();

    private static final Gson COMPACT_GSON = new GsonBuilder()
            .serializeNulls()
            .disableHtmlEscaping()
            .create();

    /**
     * Parses a raw JWT string into the provided JWTTokenModel.
     */
    public static boolean parseToken(String rawToken, JWTTokenModel model) {
        if (rawToken == null || rawToken.trim().isEmpty()) {
            model.clear();
            return false;
        }

        String cleaned = rawToken.trim();
        // Remove "Bearer " prefix if user accidentally pasted it with Bearer
        if (cleaned.regionMatches(true, 0, "bearer ", 0, 7)) {
            cleaned = cleaned.substring(7).trim();
        }

        model.setRawToken(cleaned);

        String[] parts = cleaned.split("\\.");
        if (parts.length < 2) {
            model.setValid(false);
            model.setParseError("Invalid JWT: expected at least 2 dot-separated parts (Header.Payload), got " + parts.length);
            return false;
        }

        try {
            // 1. Decode Header
            byte[] headerBytes = base64UrlDecode(parts[0]);
            String headerStr = new String(headerBytes, StandardCharsets.UTF_8);
            model.setRawHeader(headerStr);

            JsonElement headerEl = JsonParser.parseString(headerStr);
            if (!headerEl.isJsonObject()) {
                model.setValid(false);
                model.setParseError("Invalid JWT Header: not a JSON Object");
                return false;
            }
            model.setPrettyHeaderJson(PRETTY_GSON.toJson(headerEl));
            model.setHeaderClaims(jsonToMap(headerEl.getAsJsonObject()));

            // 2. Decode Payload
            byte[] payloadBytes = base64UrlDecode(parts[1]);
            String payloadStr = new String(payloadBytes, StandardCharsets.UTF_8);
            model.setRawPayload(payloadStr);

            JsonElement payloadEl = JsonParser.parseString(payloadStr);
            if (!payloadEl.isJsonObject()) {
                model.setValid(false);
                model.setParseError("Invalid JWT Payload: not a JSON Object");
                return false;
            }
            model.setPrettyPayloadJson(PRETTY_GSON.toJson(payloadEl));
            model.setPayloadClaims(jsonToMap(payloadEl.getAsJsonObject()));

            // 3. Signature
            if (parts.length >= 3) {
                model.setSignature(parts[2]);
            } else {
                model.setSignature("");
            }

            model.setValid(true);
            model.setParseError(null);
            return true;
        } catch (Exception e) {
            model.setValid(false);
            model.setParseError("Parsing error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Decodes Base64Url string into raw bytes with padding support.
     */
    public static byte[] base64UrlDecode(String str) {
        String base64 = str.replace('-', '+').replace('_', '/');
        int padding = 4 - (base64.length() % 4);
        if (padding > 0 && padding < 4) {
            base64 += "=".repeat(padding);
        }
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Converts a JsonObject to a LinkedHashMap preserving order.
     */
    private static Map<String, Object> jsonToMap(JsonObject obj) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
            map.put(entry.getKey(), jsonElementToJava(entry.getValue()));
        }
        return map;
    }

    private static Object jsonElementToJava(JsonElement el) {
        if (el == null || el.isJsonNull()) {
            return null;
        }
        if (el.isJsonPrimitive()) {
            JsonPrimitive prim = el.getAsJsonPrimitive();
            if (prim.isBoolean()) return prim.getAsBoolean();
            if (prim.isNumber()) {
                Number num = prim.getAsNumber();
                double d = num.doubleValue();
                if (d == Math.floor(d) && !Double.isInfinite(d)) {
                    long l = num.longValue();
                    return l;
                }
                return num;
            }
            return prim.getAsString();
        }
        if (el.isJsonArray()) {
            List<Object> list = new ArrayList<>();
            for (JsonElement item : el.getAsJsonArray()) {
                list.add(jsonElementToJava(item));
            }
            return list;
        }
        if (el.isJsonObject()) {
            return jsonToMap(el.getAsJsonObject());
        }
        return el.toString();
    }

    /**
     * Formats any claim value into a clean, displayable single-line or JSON representation.
     */
    public static String formatClaimValue(Object val) {
        if (val == null) {
            return "null";
        }
        if (val instanceof String || val instanceof Number || val instanceof Boolean) {
            return String.valueOf(val);
        }
        try {
            return COMPACT_GSON.toJson(val);
        } catch (Exception e) {
            return String.valueOf(val);
        }
    }

    /**
     * Formats any claim value for the multi-line detailed inspector.
     */
    public static String formatClaimValuePretty(Object val) {
        if (val == null) {
            return "null";
        }
        if (val instanceof String || val instanceof Number || val instanceof Boolean) {
            return String.valueOf(val);
        }
        try {
            return PRETTY_GSON.toJson(val);
        } catch (Exception e) {
            return String.valueOf(val);
        }
    }

    /**
     * Extracts first JWT token found in arbitrary text.
     */
    public static String extractTokenFromText(String text) {
        if (text == null || text.trim().isEmpty()) {
            return null;
        }

        // First try Bearer header regex
        Matcher bearerMatcher = BEARER_REGEX.matcher(text);
        if (bearerMatcher.find()) {
            String candidate = bearerMatcher.group(1).trim();
            if (candidate.contains(".")) {
                return candidate;
            }
        }

        // Try standard JWT regex
        Matcher jwtMatcher = JWT_REGEX.matcher(text);
        if (jwtMatcher.find()) {
            return jwtMatcher.group();
        }

        return null;
    }

    /**
     * Extracts all JWT tokens found in arbitrary text.
     */
    public static List<String> extractAllTokensFromText(String text) {
        List<String> list = new ArrayList<>();
        if (text == null || text.isEmpty()) return list;

        Matcher jwtMatcher = JWT_REGEX.matcher(text);
        while (jwtMatcher.find()) {
            String token = jwtMatcher.group();
            if (!list.contains(token)) {
                list.add(token);
            }
        }
        return list;
    }

    /**
     * Inspects an HttpRequest to locate any embedded JWT (Authorization header, cookies, body).
     */
    public static String extractFromHttpRequest(HttpRequest request) {
        if (request == null) return null;

        // 1. Authorization header
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase("Authorization") ||
                header.name().equalsIgnoreCase("X-Access-Token") ||
                header.name().equalsIgnoreCase("Token") ||
                header.name().equalsIgnoreCase("JWT")) {
                String token = extractTokenFromText(header.value());
                if (token != null) return token;
            }
        }

        // 2. Cookie headers
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase("Cookie")) {
                String token = extractTokenFromText(header.value());
                if (token != null) return token;
            }
        }

        // 3. Body
        if (request.body() != null && request.body().length() > 0) {
            String token = extractTokenFromText(request.bodyToString());
            if (token != null) return token;
        }

        return null;
    }

    /**
     * Inspects an HttpResponse to locate any embedded JWT (Set-Cookie, body).
     */
    public static String extractFromHttpResponse(HttpResponse response) {
        if (response == null) return null;

        // 1. Set-Cookie headers
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String token = extractTokenFromText(header.value());
                if (token != null) return token;
            }
        }

        // 2. Response body
        if (response.body() != null && response.body().length() > 0) {
            String token = extractTokenFromText(response.bodyToString());
            if (token != null) return token;
        }

        return null;
    }
}
