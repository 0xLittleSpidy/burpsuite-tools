// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
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
        if (jsonPath == null || !Files.exists(jsonPath)) {
            api.logging().logToOutput("[PayloadInjector] " + JSON_FILENAME + " not found at: " + jsonPath + " — list empty.");
            entries.clear();
            notifyListeners();
            return;
        }

        try {
            String json = Files.readString(jsonPath);
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
                            raw.sourceType != null ? raw.sourceType : "Manual",
                            raw.sourceFile != null ? raw.sourceFile : "N/A"
                    ));
                }
            }
            entries.clear();
            entries.addAll(loaded);
            api.logging().logToOutput("[PayloadInjector] Loaded " + entries.size() + " smuggling payloads from " + jsonPath);
        } catch (Exception ex) {
            api.logging().logToError("[PayloadInjector] Failed to parse " + JSON_FILENAME + ": " + ex.getMessage());
            entries.clear();
        }
        notifyListeners();
    }

    public synchronized void save() {
        Path jsonPath = resolveJsonPath();
        if (jsonPath == null) {
            api.logging().logToError("[PayloadInjector] Cannot save " + JSON_FILENAME + " — path unresolvable.");
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
                r.sourceType = e.getSourceType();
                r.sourceFile = e.getSourceFile();
                return r;
            }).collect(Collectors.toList());

            Files.writeString(jsonPath, gson.toJson(rawList));
            api.logging().logToOutput("[PayloadInjector] Saved " + entries.size() + " smuggling payloads to " + jsonPath);
        } catch (Exception ex) {
            api.logging().logToError("[PayloadInjector] Failed to save " + JSON_FILENAME + ": " + ex.getMessage());
        }
    }

    public List<SmugglingPayloadEntry> getEntries() {
        return Collections.unmodifiableList(entries);
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
        try {
            String jarPath = api.extension().filename();
            return Paths.get(jarPath).getParent().resolve(JSON_FILENAME);
        } catch (Exception ex) {
            api.logging().logToError("[PayloadInjector] Could not determine JAR location for " + JSON_FILENAME + ": " + ex.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unused")
    private static class RawSmugglingPayload {
        String name;
        String description;
        Map<String, String> headers;
        String body;
        String sourceType;
        String sourceFile;
    }
}
