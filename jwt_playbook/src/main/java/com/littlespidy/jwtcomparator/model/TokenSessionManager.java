// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

import com.google.gson.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Handles serializing and deserializing JWT comparison sessions to and from JSON.
 * Supports standard comparator format, array of token objects, key-value mappings, and raw token lists.
 * Preserves ignored claim keys configuration across sessions.
 */
public class TokenSessionManager {

    private static final Gson PRETTY_GSON = new GsonBuilder()
            .setPrettyPrinting()
            .serializeNulls()
            .disableHtmlEscaping()
            .create();

    public static class ExportedToken {
        private int slotIndex;
        private String name;
        private String rawToken;

        public ExportedToken() {}

        public ExportedToken(int slotIndex, String name, String rawToken) {
            this.slotIndex = slotIndex;
            this.name = name;
            this.rawToken = rawToken;
        }

        public int getSlotIndex() {
            return slotIndex;
        }

        public void setSlotIndex(int slotIndex) {
            this.slotIndex = slotIndex;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getRawToken() {
            return rawToken;
        }

        public void setRawToken(String rawToken) {
            this.rawToken = rawToken;
        }
    }

    public static class SessionData {
        private List<ExportedToken> tokens = new ArrayList<>();
        private List<String> ignoredClaims = new ArrayList<>();

        public SessionData() {}

        public SessionData(List<ExportedToken> tokens, List<String> ignoredClaims) {
            this.tokens = tokens != null ? tokens : new ArrayList<>();
            this.ignoredClaims = ignoredClaims != null ? ignoredClaims : new ArrayList<>();
        }

        public List<ExportedToken> getTokens() {
            return tokens;
        }

        public void setTokens(List<ExportedToken> tokens) {
            this.tokens = tokens;
        }

        public List<String> getIgnoredClaims() {
            return ignoredClaims;
        }

        public void setIgnoredClaims(List<String> ignoredClaims) {
            this.ignoredClaims = ignoredClaims;
        }
    }

    /**
     * Serializes token list into a formatted JSON string.
     */
    public static String exportToJson(List<JWTTokenModel> tokens) {
        return exportToJson(tokens, Collections.emptyList());
    }

    /**
     * Serializes token list and ignored claims into a formatted JSON string.
     */
    public static String exportToJson(List<JWTTokenModel> tokens, Collection<String> ignoredClaims) {
        JsonObject root = new JsonObject();
        root.addProperty("application", "JWT Comparator");
        root.addProperty("version", "1.0");
        root.addProperty("exportedAt", Instant.now().toString());

        if (ignoredClaims != null && !ignoredClaims.isEmpty()) {
            JsonArray ignArr = new JsonArray();
            for (String ic : ignoredClaims) {
                if (ic != null && !ic.trim().isEmpty()) {
                    ignArr.add(ic.trim().toLowerCase());
                }
            }
            root.add("ignoredClaims", ignArr);
        }

        JsonArray tokenArray = new JsonArray();
        if (tokens != null) {
            for (int i = 0; i < tokens.size(); i++) {
                JWTTokenModel tm = tokens.get(i);
                JsonObject tObj = new JsonObject();
                tObj.addProperty("slotIndex", tm.getSlotIndex());
                tObj.addProperty("name", tm.getLabel());
                tObj.addProperty("rawToken", tm.getRawToken());
                tokenArray.add(tObj);
            }
        }
        root.add("tokens", tokenArray);

        return PRETTY_GSON.toJson(root);
    }

    /**
     * Parses JSON string into a list of ExportedToken objects.
     */
    public static List<ExportedToken> importFromJson(String jsonContent) throws IllegalArgumentException {
        return importSessionFromJson(jsonContent).getTokens();
    }

    /**
     * Parses JSON string into a complete SessionData object with tokens and ignored claims.
     * Supports:
     * 1. Standard format: { "tokens": [...], "ignoredClaims": [...] }
     * 2. Direct array: [ { "name": "...", "token": "..." } ] or [ "eyJ...", "eyJ..." ]
     * 3. Key-Value map: { "Admin": "eyJ...", "User": "eyJ..." }
     */
    public static SessionData importSessionFromJson(String jsonContent) throws IllegalArgumentException {
        SessionData session = new SessionData();
        if (jsonContent == null || jsonContent.trim().isEmpty()) {
            return session;
        }

        try {
            JsonElement root = JsonParser.parseString(jsonContent.trim());

            if (root.isJsonObject()) {
                JsonObject obj = root.getAsJsonObject();

                // Extract ignored claims if present
                if (obj.has("ignoredClaims") && obj.get("ignoredClaims").isJsonArray()) {
                    JsonArray ignArr = obj.getAsJsonArray("ignoredClaims");
                    for (JsonElement el : ignArr) {
                        if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
                            session.getIgnoredClaims().add(el.getAsString().trim().toLowerCase());
                        }
                    }
                }

                if (obj.has("tokens") && obj.get("tokens").isJsonArray()) {
                    JsonArray arr = obj.getAsJsonArray("tokens");
                    int index = 1;
                    for (JsonElement el : arr) {
                        if (el.isJsonObject()) {
                            JsonObject to = el.getAsJsonObject();
                            String name = extractStringField(to, "name", "label", "domain");
                            if (name == null || name.isEmpty()) {
                                name = "Token " + index;
                            }
                            String raw = extractStringField(to, "rawToken", "token", "jwt", "raw");
                            int slot = to.has("slotIndex") && to.get("slotIndex").isJsonPrimitive() ?
                                    to.get("slotIndex").getAsInt() : index;
                            session.getTokens().add(new ExportedToken(slot, name, raw != null ? raw : ""));
                            index++;
                        }
                    }
                } else {
                    // Check if map of tokenName -> rawToken
                    int index = 1;
                    for (String key : obj.keySet()) {
                        if ("ignoredClaims".equalsIgnoreCase(key) || "version".equalsIgnoreCase(key)
                                || "application".equalsIgnoreCase(key) || "exportedAt".equalsIgnoreCase(key)) {
                            continue;
                        }
                        JsonElement val = obj.get(key);
                        if (val.isJsonPrimitive() && val.getAsJsonPrimitive().isString()) {
                            session.getTokens().add(new ExportedToken(index, key, val.getAsString()));
                            index++;
                        } else if (val.isJsonObject()) {
                            JsonObject subObj = val.getAsJsonObject();
                            String raw = extractStringField(subObj, "rawToken", "token", "jwt", "raw");
                            session.getTokens().add(new ExportedToken(index, key, raw != null ? raw : ""));
                            index++;
                        }
                    }
                }
            } else if (root.isJsonArray()) {
                JsonArray arr = root.getAsJsonArray();
                int index = 1;
                for (JsonElement el : arr) {
                    if (el.isJsonObject()) {
                        JsonObject to = el.getAsJsonObject();
                        String name = extractStringField(to, "name", "label", "domain");
                        if (name == null || name.isEmpty()) {
                            name = "Token " + index;
                        }
                        String raw = extractStringField(to, "rawToken", "token", "jwt", "raw");
                        int slot = to.has("slotIndex") && to.get("slotIndex").isJsonPrimitive() ?
                                to.get("slotIndex").getAsInt() : index;
                        session.getTokens().add(new ExportedToken(slot, name, raw != null ? raw : ""));
                    } else if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
                        session.getTokens().add(new ExportedToken(index, "Token " + index, el.getAsString()));
                    }
                    index++;
                }
            }
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to parse tokens JSON: " + ex.getMessage(), ex);
        }

        return session;
    }

    private static String extractStringField(JsonObject obj, String... candidateFields) {
        for (String field : candidateFields) {
            if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                return obj.get(field).getAsString();
            }
        }
        return null;
    }
}
