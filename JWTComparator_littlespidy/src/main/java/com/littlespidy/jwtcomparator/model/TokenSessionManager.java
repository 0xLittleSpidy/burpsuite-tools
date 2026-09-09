// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

import com.google.gson.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles serializing and deserializing JWT comparison sessions to and from JSON.
 * Supports standard comparator format, array of token objects, key-value mappings, and raw token lists.
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

    /**
     * Serializes token list into a formatted JSON string.
     */
    public static String exportToJson(List<JWTTokenModel> tokens) {
        JsonObject root = new JsonObject();
        root.addProperty("application", "JWT Comparator");
        root.addProperty("version", "1.0");
        root.addProperty("exportedAt", Instant.now().toString());

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
     * Supports:
     * 1. Standard format: { "tokens": [ { "name": "...", "rawToken": "..." } ] }
     * 2. Direct array: [ { "name": "...", "token": "..." } ] or [ "eyJ...", "eyJ..." ]
     * 3. Key-Value map: { "Admin": "eyJ...", "User": "eyJ..." }
     */
    public static List<ExportedToken> importFromJson(String jsonContent) throws IllegalArgumentException {
        List<ExportedToken> result = new ArrayList<>();
        if (jsonContent == null || jsonContent.trim().isEmpty()) {
            return result;
        }

        try {
            JsonElement root = JsonParser.parseString(jsonContent.trim());

            if (root.isJsonObject()) {
                JsonObject obj = root.getAsJsonObject();
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
                            result.add(new ExportedToken(slot, name, raw != null ? raw : ""));
                            index++;
                        }
                    }
                } else {
                    // Check if map of tokenName -> rawToken
                    int index = 1;
                    for (String key : obj.keySet()) {
                        JsonElement val = obj.get(key);
                        if (val.isJsonPrimitive() && val.getAsJsonPrimitive().isString()) {
                            result.add(new ExportedToken(index, key, val.getAsString()));
                            index++;
                        } else if (val.isJsonObject()) {
                            JsonObject subObj = val.getAsJsonObject();
                            String raw = extractStringField(subObj, "rawToken", "token", "jwt", "raw");
                            result.add(new ExportedToken(index, key, raw != null ? raw : ""));
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
                        result.add(new ExportedToken(slot, name, raw != null ? raw : ""));
                    } else if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
                        result.add(new ExportedToken(index, "Token " + index, el.getAsString()));
                    }
                    index++;
                }
            }
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to parse tokens JSON: " + ex.getMessage(), ex);
        }

        return result;
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
