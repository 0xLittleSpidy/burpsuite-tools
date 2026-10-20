// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.model;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.littlespidy.requestsmugglinginspector.storage.SmugglingSessionDTO_littlespidy;

import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Loads, caches, and persists the list of {@link PayloadEntry} objects from/to
 * {@code smuggling-payloads.json}, which must be placed in the same directory
 * as the extension JAR.
 *
 * <p>Call {@link #reload()} to re-read the file from disk (e.g. when the user
 * clicks "Reload from JSON" in the Payloads tab).
 *
 * <p>Call {@link #addEntry(PayloadEntry)} or {@link #removeEntry(int)} to
 * mutate the list; both methods call {@link #save()} automatically so the JSON
 * file is always kept in sync with the in-memory state.
 *
 * @author littlespidy
 */
public class PayloadStore {

    private static final String JSON_FILENAME = "smuggling-payloads.json";

    private final MontoyaApi api;
    private List<PayloadEntry> entries = new ArrayList<>();

    public PayloadStore(MontoyaApi api) {
        this.api = api;
        reload();
    }

    // -- Read operations --------------------------------------------------------

    /**
     * Re-reads {@code smuggling-payloads.json} from disk and rebuilds the
     * in-memory payload list. Logs progress and errors to Burp's output panel.
     */
    public void reload() {
        Path jsonPath = resolveJsonPath();

        if (jsonPath == null) {
            api.logging().logToOutput(
                    "[RSI] Could not resolve extension JAR path - payloads will be empty.");
            entries = new ArrayList<>();
            return;
        }

        if (!Files.exists(jsonPath)) {
            api.logging().logToOutput(
                    "[RSI] " + JSON_FILENAME + " not found at: " + jsonPath
                    + " - payloads will be empty.");
            entries = new ArrayList<>();
            return;
        }

        try {
            String json = Files.readString(jsonPath);
            entries = parse(json);
            api.logging().logToOutput(
                    "[RSI] Loaded " + entries.size() + " payload(s) from " + jsonPath);
        } catch (Exception ex) {
            api.logging().logToError(
                    "[RSI] Failed to parse " + JSON_FILENAME + ": " + ex.getMessage());
            entries = new ArrayList<>();
        }
    }

    /** Returns an unmodifiable view of the currently loaded payloads. */
    public List<PayloadEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public SmugglingSessionDTO_littlespidy.SessionRootDTO exportSessionDTO() {
        SmugglingSessionDTO_littlespidy.SessionRootDTO root = new SmugglingSessionDTO_littlespidy.SessionRootDTO();
        for (PayloadEntry entry : entries) {
            SmugglingSessionDTO_littlespidy.SmugglingPayloadDTO dto = new SmugglingSessionDTO_littlespidy.SmugglingPayloadDTO();
            dto.name = entry.getName();
            dto.description = entry.getDescription();
            dto.headers = new LinkedHashMap<>(entry.getHeaders());
            dto.body = entry.getBody();
            root.payloads.add(dto);
        }
        return root;
    }

    public void importSessionDTO(SmugglingSessionDTO_littlespidy.SessionRootDTO root) {
        List<PayloadEntry> list = new ArrayList<>();
        if (root != null && root.payloads != null) {
            for (SmugglingSessionDTO_littlespidy.SmugglingPayloadDTO dto : root.payloads) {
                list.add(new PayloadEntry(dto.name, dto.description, dto.headers, dto.body));
            }
        }
        this.entries = list;
    }

    public void clear() {
        this.entries = new ArrayList<>();
    }

    // -- Write operations -------------------------------------------------------

    /**
     * Appends {@code entry} to the in-memory list and immediately persists
     * the full list to {@code smuggling-payloads.json} via {@link #save()}.
     *
     * @param entry the new payload to add (must not be {@code null})
     */
    public void addEntry(PayloadEntry entry) {
        entries.add(entry);
        save();
    }

    /**
     * Removes the payload at position {@code index} from the in-memory list
     * and immediately persists the result via {@link #save()}.
     *
     * @param index zero-based index into the current payload list (model row)
     */
    public void removeEntry(int index) {
        if (index >= 0 && index < entries.size()) {
            entries.remove(index);
            save();
        }
    }

    /**
     * Serialises the current in-memory payload list to {@code smuggling-payloads.json}
     * using Gson pretty-printing. Called automatically by {@link #addEntry} and
     * {@link #removeEntry}; may also be called directly if needed.
     */
    public void save() {
        Path jsonPath = resolveJsonPath();
        if (jsonPath == null) {
            api.logging().logToError(
                    "[RSI] Cannot save - JAR path could not be resolved.");
            return;
        }
        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            List<RawPayload> raw = entries.stream().map(e -> {
                RawPayload r  = new RawPayload();
                r.name        = e.getName();
                r.description = e.getDescription();
                r.headers     = new LinkedHashMap<>(e.getHeaders());
                r.body        = e.getBody();
                return r;
            }).collect(Collectors.toList());

            Files.writeString(jsonPath, gson.toJson(raw));
            api.logging().logToOutput(
                    "[RSI] Saved " + entries.size() + " payload(s) to " + jsonPath);
        } catch (Exception ex) {
            api.logging().logToError(
                    "[RSI] Failed to save payloads: " + ex.getMessage());
        }
    }

    // -- Private helpers --------------------------------------------------------

    /**
     * Resolves the expected JSON file path by taking the directory of the
     * extension JAR (via {@code api.extension().filename()}) and appending
     * {@value #JSON_FILENAME}.
     */
    private Path resolveJsonPath() {
        try {
            String jarPath = api.extension().filename();
            return Paths.get(jarPath).getParent().resolve(JSON_FILENAME);
        } catch (Exception ex) {
            api.logging().logToError(
                    "[RSI] Could not determine JAR location: " + ex.getMessage());
            return null;
        }
    }

    /**
     * Parses the JSON array using Gson into a list of {@link PayloadEntry}
     * objects, skipping any entries that are missing a {@code name} field.
     */
    private List<PayloadEntry> parse(String json) {
        Gson gson = new Gson();
        Type listType = new TypeToken<List<RawPayload>>() {}.getType();
        List<RawPayload> rawList = gson.fromJson(json, listType);

        List<PayloadEntry> result = new ArrayList<>();
        if (rawList == null) return result;

        for (RawPayload raw : rawList) {
            if (raw.name == null || raw.name.isBlank()) continue;

            Map<String, String> headers = raw.headers != null
                    ? raw.headers
                    : new LinkedHashMap<>();

            result.add(new PayloadEntry(
                    raw.name,
                    raw.description,
                    headers,
                    raw.body));
        }
        return result;
    }

    // -- Inner POJO for Gson ----------------------------------------------------

    /** Internal data-transfer object used by Gson during serialisation and deserialisation. */
    @SuppressWarnings("unused")
    private static class RawPayload {
        String name;
        String description;
        Map<String, String> headers;
        String body;
    }
}
