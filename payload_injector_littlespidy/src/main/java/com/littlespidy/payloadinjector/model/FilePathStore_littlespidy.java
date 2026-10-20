// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.File;
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
 * Dedicated storage and persistence manager for target file paths.
 * Backed by dedicated JSON files (linux_file_paths_littlespidy.json and windows_file_paths_littlespidy.json).
 *
 * @author littlespidy
 */
public class FilePathStore_littlespidy {

    private final MontoyaApi api;
    private final String fileName;
    private final String defaultPlatform;
    private final List<FilePathEntry_littlespidy> entries = new ArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public FilePathStore_littlespidy(MontoyaApi api, String fileName, String defaultPlatform) {
        this.api = api;
        this.fileName = fileName;
        this.defaultPlatform = (defaultPlatform != null) ? defaultPlatform : "Linux";
        reload();
    }

    public String getFileName() {
        return fileName;
    }

    public String getDefaultPlatform() {
        return defaultPlatform;
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

        // Attempt to load from bundled classpath resource if file does not yet exist on disk
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
        Type listType = new TypeToken<List<RawFilePath>>() {}.getType();
        List<RawFilePath> rawList = gson.fromJson(json, listType);

        List<FilePathEntry_littlespidy> loaded = new ArrayList<>();
        if (rawList != null) {
            for (RawFilePath raw : rawList) {
                if (raw.path == null || raw.path.isBlank()) continue;
                String category = (raw.category != null && !raw.category.isBlank()) ? raw.category : "General";
                String platform = (raw.platform != null && !raw.platform.isBlank()) ? raw.platform : defaultPlatform;
                loaded.add(new FilePathEntry_littlespidy(
                        raw.id != null ? raw.id : java.util.UUID.randomUUID().toString(),
                        raw.path,
                        category,
                        raw.description != null ? raw.description : "",
                        platform,
                        true,
                        "Default",
                        fileName
                ));
            }
        }
        entries.clear();
        entries.addAll(loaded);
        if (api != null && api.logging() != null) {
            api.logging().logToOutput("[PayloadInjector] Loaded " + entries.size() + " file paths from " + sourceDesc);
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
            List<RawFilePath> rawList = new ArrayList<>();
            for (FilePathEntry_littlespidy e : entries) {
                RawFilePath r = new RawFilePath();
                r.id = e.getId();
                r.path = e.getPath();
                r.category = e.getCategory();
                r.description = e.getDescription();
                r.platform = e.getPlatform();
                rawList.add(r);
            }
            Files.writeString(jsonPath, gson.toJson(rawList), StandardCharsets.UTF_8);
            if (api != null && api.logging() != null) {
                api.logging().logToOutput("[PayloadInjector] Saved " + entries.size() + " file paths to " + jsonPath);
            }
        } catch (Exception ex) {
            if (api != null && api.logging() != null) {
                api.logging().logToError("[PayloadInjector] Failed to save " + fileName + ": " + ex.getMessage());
            }
        }
    }

    public List<FilePathEntry_littlespidy> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public synchronized void addEntry(FilePathEntry_littlespidy entry) {
        entries.add(entry);
        save();
        notifyListeners();
    }

    public synchronized void addEntries(List<FilePathEntry_littlespidy> newEntries) {
        if (newEntries != null && !newEntries.isEmpty()) {
            entries.addAll(newEntries);
            save();
            notifyListeners();
        }
    }

    public synchronized void updateEntry(int index, FilePathEntry_littlespidy entry) {
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

    public synchronized void replaceEntries(List<FilePathEntry_littlespidy> newEntries) {
        if (newEntries != null) {
            entries.clear();
            entries.addAll(newEntries);
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

        Path currentDirFile = Paths.get(fileName);
        if (Files.exists(currentDirFile)) {
            return currentDirFile;
        }

        try {
            String jarPath = getClass().getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            if (jarPath != null) {
                File jarFile = new File(jarPath);
                File dir = jarFile.isDirectory() ? jarFile : jarFile.getParentFile();
                if (dir != null) {
                    Path candidate = dir.toPath().resolve(fileName);
                    if (Files.exists(candidate)) {
                        return candidate;
                    }
                }
            }
        } catch (Exception ignored) {}

        return currentDirFile;
    }

    private static class RawFilePath {
        String id;
        String path;
        String category;
        String description;
        String platform;
    }
}
