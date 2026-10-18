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
        if (jsonPath == null || !Files.exists(jsonPath)) {
            api.logging().logToOutput("[PayloadInjector] " + fileName + " not found at: " + jsonPath + " — list empty.");
            entries.clear();
            notifyListeners();
            return;
        }

        try {
            String json = Files.readString(jsonPath);
            Gson gson = new Gson();
            Type listType = new TypeToken<List<RawParamPayload>>() {}.getType();
            List<RawParamPayload> rawList = gson.fromJson(json, listType);

            List<ParamPayloadEntry> loaded = new ArrayList<>();
            if (rawList != null) {
                for (RawParamPayload raw : rawList) {
                    if (raw.name == null || raw.name.isBlank()) continue;
                    String srcType = (raw.sourceType != null && !raw.sourceType.isBlank()) ? raw.sourceType : "Manual";
                    String srcFile = (raw.sourceFile != null && !raw.sourceFile.isBlank()) ? raw.sourceFile : "N/A";
                    loaded.add(new ParamPayloadEntry(
                            raw.id != null ? raw.id : java.util.UUID.randomUUID().toString(),
                            raw.name,
                            raw.template != null ? raw.template : "",
                            raw.description != null ? raw.description : "",
                            raw.enabled != null ? raw.enabled : true,
                            srcType,
                            srcFile
                    ));
                }
            }
            entries.clear();
            entries.addAll(loaded);
            api.logging().logToOutput("[PayloadInjector] Loaded " + entries.size() + " payloads from " + jsonPath);
        } catch (Exception ex) {
            api.logging().logToError("[PayloadInjector] Failed to parse " + fileName + ": " + ex.getMessage());
            entries.clear();
        }
        notifyListeners();
    }

    public synchronized void save() {
        Path jsonPath = resolveJsonPath();
        if (jsonPath == null) {
            api.logging().logToError("[PayloadInjector] Cannot save " + fileName + " — path unresolvable.");
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
                r.enabled = e.isEnabled();
                r.sourceType = e.getSourceType();
                r.sourceFile = e.getSourceFile();
                rawList.add(r);
            }
            Files.writeString(jsonPath, gson.toJson(rawList));
            api.logging().logToOutput("[PayloadInjector] Saved " + entries.size() + " payloads to " + jsonPath);
        } catch (Exception ex) {
            api.logging().logToError("[PayloadInjector] Failed to save " + fileName + ": " + ex.getMessage());
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
        try {
            String jarPath = api.extension().filename();
            return Paths.get(jarPath).getParent().resolve(fileName);
        } catch (Exception ex) {
            api.logging().logToError("[PayloadInjector] Could not determine JAR location for " + fileName + ": " + ex.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unused")
    private static class RawParamPayload {
        String id;
        String name;
        String template;
        String description;
        Boolean enabled;
        String sourceType;
        String sourceFile;
    }
}
