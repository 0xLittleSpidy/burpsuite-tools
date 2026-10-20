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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated JSON store for parameter-based payload categories (XSS, CSTI, SQL).
 * Reads from and writes to the configured JSON file located in the same directory as the JAR.
 *
 * @author littlespidy
 */
public class ParamPayloadStore {

    private final MontoyaApi api;
    private final String fileName;
    private final List<ParamPayloadEntry> entries = new CopyOnWriteArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public ParamPayloadStore(MontoyaApi api, String fileName) {
        this.api = api;
        this.fileName = fileName;
        reload();
    }

    public String getFileName() {
        return fileName;
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
                    api.logging().logToError("[PayloadInjector] Failed to parse " + fileName + ": " + ex.getMessage());
                }
            }
        }

        // Classpath resource fallback from bundled JAR
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(fileName)) {
            if (in != null) {
                String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                parseAndSet(json, "bundled JAR classpath:" + fileName);

                // Auto-extract to disk next to JAR if writable
                if (jsonPath != null && !Files.exists(jsonPath)) {
                    try {
                        if (jsonPath.getParent() != null) {
                            Files.createDirectories(jsonPath.getParent());
                        }
                        Files.writeString(jsonPath, json, StandardCharsets.UTF_8);
                        if (api != null && api.logging() != null) {
                            api.logging().logToOutput("[PayloadInjector] Extracted bundled " + fileName + " to " + jsonPath);
                        }
                    } catch (Exception ignored) {}
                }
                return;
            }
        } catch (Exception ex) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("[PayloadInjector] Failed to read bundled " + fileName + ": " + ex.getMessage());
            }
        }

        if (api != null && api.logging() != null) {
            api.logging().logToOutput("[PayloadInjector] " + fileName + " not found on disk (" + jsonPath + ") or in JAR resource - list empty.");
        }
        entries.clear();
        notifyListeners();
    }

    private void parseAndSet(String json, String sourceDesc) {
        Gson gson = new Gson();
        Type listType = new TypeToken<List<RawParamPayload>>() {}.getType();
        List<RawParamPayload> rawList = gson.fromJson(json, listType);

        List<ParamPayloadEntry> loaded = new ArrayList<>();
        if (rawList != null) {
            for (RawParamPayload raw : rawList) {
                if (raw.name == null || raw.name.isBlank()) continue;
                loaded.add(new ParamPayloadEntry(
                        raw.id != null ? raw.id : java.util.UUID.randomUUID().toString(),
                        raw.name,
                        raw.template != null ? raw.template : "",
                        raw.description != null ? raw.description : "",
                        true,
                        "Manual",
                        "N/A",
                        raw.platform != null ? raw.platform : ""
                ));
            }
        }
        entries.clear();
        entries.addAll(loaded);
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("[PayloadInjector] Loaded " + entries.size() + " payloads from " + sourceDesc);
        }
        notifyListeners();
    }

    public synchronized void save() {
        Path jsonPath = resolveJsonPath();
        if (jsonPath == null) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("[PayloadInjector] Cannot save " + fileName + " - path unresolvable.");
            }
            return;
        }

        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            List<RawParamPayload> rawList = new ArrayList<>();
            for (ParamPayloadEntry e : entries) {
                RawParamPayload r = new RawParamPayload();
                r.id = e.getId();
                r.name = e.getName();
                r.template = e.getTemplate();
                r.description = e.getDescription();
                r.platform = (e.getPlatform() != null && !e.getPlatform().isBlank()) ? e.getPlatform() : null;
                rawList.add(r);
            }
            Files.writeString(jsonPath, gson.toJson(rawList));
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("[PayloadInjector] Saved " + entries.size() + " payloads to " + jsonPath);
            }
        } catch (Exception ex) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("[PayloadInjector] Failed to save " + fileName + ": " + ex.getMessage());
            }
        }
    }

    public List<ParamPayloadEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public synchronized void addEntry(ParamPayloadEntry entry) {
        entries.add(entry);
        save();
        notifyListeners();
    }

    public synchronized void addEntries(List<ParamPayloadEntry> newEntries) {
        if (newEntries != null && !newEntries.isEmpty()) {
            entries.addAll(newEntries);
            save();
            notifyListeners();
        }
    }

    public synchronized void replaceEntries(List<ParamPayloadEntry> newEntries) {
        if (newEntries != null) {
            entries.clear();
            entries.addAll(newEntries);
            save();
            notifyListeners();
        }
    }

    public synchronized void updateEntry(int index, ParamPayloadEntry entry) {
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

    public Path resolveStorageDirectory() {
        Path jsonPath = resolveJsonPath();
        if (jsonPath != null && jsonPath.getParent() != null) {
            return jsonPath.getParent();
        }
        return Paths.get(".");
    }

    private Path resolveJsonPath() {
        if (api != null) {
            try {
                String jarPath = api.extension().filename();
                if (jarPath != null && !jarPath.isBlank()) {
                    return Paths.get(jarPath).toAbsolutePath().getParent().resolve(fileName);
                }
            } catch (Exception ex) {
                if (api.logging() != null) {
                    api.logging().logToError("[PayloadInjector] Could not determine JAR location for " + fileName + ": " + ex.getMessage());
                }
            }
        }
        Path currentDir = Paths.get(fileName);
        if (Files.exists(currentDir)) {
            return currentDir;
        }
        return currentDir;
    }

    @SuppressWarnings("unused")
    private static class RawParamPayload {
        String id;
        String name;
        String template;
        String description;
        String platform;
    }
}
