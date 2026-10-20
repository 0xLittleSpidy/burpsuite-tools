// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated JSON store for HTTP request smuggling payloads.
 * Reads from and writes to {@code http_request_smuggling_payloads.json} next to the JAR.
 *
 * @author littlespidy
 */
public class SmugglingPayloadStore {

    private static final String JSON_FILENAME = "http_request_smuggling_payloads.json";

    private final MontoyaApi api;
    private final List<SmugglingPayloadEntry> entries = new CopyOnWriteArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public SmugglingPayloadStore(MontoyaApi api) {
        this.api = api;
        reload();
    }

    public synchronized void reload() {
        Path jsonPath = resolveJsonPath();
        if (jsonPath != null && Files.exists(jsonPath)) {
            try {
                String json = Files.readString(jsonPath, StandardCharsets.UTF_8);
                parseAndSet(json, jsonPath.toString());
                return;
            } catch (Exception ex) {
                if (api != null && api.logging() != null) {
                    api.logging().logToError("[PayloadInjector] Failed to parse " + JSON_FILENAME + ": " + ex.getMessage());
                }
            }
        }

        // Classpath resource fallback from bundled JAR
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(JSON_FILENAME)) {
            if (in != null) {
                String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                parseAndSet(json, "bundled JAR classpath:" + JSON_FILENAME);

                // Auto-extract to disk next to JAR if writable
                if (jsonPath != null && !Files.exists(jsonPath)) {
                    try {
                        if (jsonPath.getParent() != null) {
                            Files.createDirectories(jsonPath.getParent());
                        }
                        Files.writeString(jsonPath, json, StandardCharsets.UTF_8);
                        if (api != null && api.logging() != null) {
                            api.logging().logToOutput("[PayloadInjector] Extracted bundled " + JSON_FILENAME + " to " + jsonPath);
                        }
                    } catch (Exception ignored) {}
                }
                return;
            }
        } catch (Exception ex) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("[PayloadInjector] Failed to read bundled " + JSON_FILENAME + ": " + ex.getMessage());
            }
        }

        if (api != null && api.logging() != null) {
            api.logging().logToOutput("[PayloadInjector] " + JSON_FILENAME + " not found on disk (" + jsonPath + ") or in JAR resource - list empty.");
        }
        entries.clear();
        notifyListeners();
    }

    private void parseAndSet(String json, String sourceDesc) {
        Gson gson = new Gson();
        Type listType = new TypeToken<List<RawSmugglingPayload>>() {}.getType();
        List<RawSmugglingPayload> rawList = gson.fromJson(json, listType);

        List<SmugglingPayloadEntry> loaded = new ArrayList<>();
        if (rawList != null) {
            for (RawSmugglingPayload raw : rawList) {
                if (raw.name == null || raw.name.isBlank()) continue;
                Map<String, String> headers = raw.headers != null ? raw.headers : new LinkedHashMap<>();
                loaded.add(new SmugglingPayloadEntry(
                        raw.name,
                        raw.description != null ? raw.description : "",
                        headers,
                        raw.body != null ? raw.body : "",
                        "Manual",
                        "N/A"
                ));
            }
        }
        entries.clear();
        entries.addAll(loaded);
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("[PayloadInjector] Loaded " + entries.size() + " smuggling payloads from " + sourceDesc);
        }
        notifyListeners();
    }

    public synchronized void save() {
        Path jsonPath = resolveJsonPath();
        if (jsonPath == null) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("[PayloadInjector] Cannot save " + JSON_FILENAME + " - path unresolvable.");
            }
            return;
        }

        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            List<RawSmugglingPayload> rawList = entries.stream().map(e -> {
                RawSmugglingPayload r = new RawSmugglingPayload();
                r.name = e.getName();
                r.description = e.getDescription();
                r.headers = new LinkedHashMap<>(e.getHeaders());
                r.body = e.getBody();
                return r;
            }).collect(Collectors.toList());

            if (jsonPath.getParent() != null) {
                Files.createDirectories(jsonPath.getParent());
            }
            Files.writeString(jsonPath, gson.toJson(rawList), StandardCharsets.UTF_8);
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("[PayloadInjector] Saved " + entries.size() + " smuggling payloads to " + jsonPath);
            }
        } catch (Exception ex) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("[PayloadInjector] Failed to save " + JSON_FILENAME + ": " + ex.getMessage());
            }
        }
    }

    public List<SmugglingPayloadEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public synchronized void replaceEntries(List<SmugglingPayloadEntry> newEntries) {
        if (newEntries != null) {
            entries.clear();
            entries.addAll(newEntries);
            save();
            notifyListeners();
        }
    }

    public synchronized void addEntry(SmugglingPayloadEntry entry) {
        entries.add(entry);
        save();
        notifyListeners();
    }

    public synchronized void updateEntry(int index, SmugglingPayloadEntry entry) {
        if (index >= 0 && index < entries.size()) {
            entries.set(index, entry);
            save();
            notifyListeners();
        }
    }

    public synchronized void removeEntry(int index) {
        if (index >= 0 && index < entries.size()) {
            entries.remove(index);
            save();
            notifyListeners();
        }
    }

    public synchronized void removeEntries(int[] modelIndices) {
        if (modelIndices == null || modelIndices.length == 0) return;
        int[] sorted = modelIndices.clone();
        java.util.Arrays.sort(sorted);
        boolean changed = false;
        for (int i = sorted.length - 1; i >= 0; i--) {
            int idx = sorted[i];
            if (idx >= 0 && idx < entries.size()) {
                entries.remove(idx);
                changed = true;
            }
        }
        if (changed) {
            save();
            notifyListeners();
        }
    }

    public void addChangeListener(Runnable listener) {
        listeners.add(listener);
    }

    public void removeChangeListener(Runnable listener) {
        listeners.remove(listener);
    }

    private void notifyListeners() {
        for (Runnable r : listeners) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }

    private Path resolveJsonPath() {
        if (api != null) {
            try {
                String jarPath = api.extension().filename();
                if (jarPath != null && !jarPath.isBlank()) {
                    return Paths.get(jarPath).toAbsolutePath().getParent().resolve(JSON_FILENAME);
                }
            } catch (Exception ex) {
                if (api.logging() != null) {
                    api.logging().logToError("[PayloadInjector] Could not determine JAR location for " + JSON_FILENAME + ": " + ex.getMessage());
                }
            }
        }
        Path currentDir = Paths.get(JSON_FILENAME);
        if (Files.exists(currentDir)) {
            return currentDir;
        }
        return currentDir;
    }

    @SuppressWarnings("unused")
    private static class RawSmugglingPayload {
        String name;
        String description;
        Map<String, String> headers;
        String body;
    }
}
