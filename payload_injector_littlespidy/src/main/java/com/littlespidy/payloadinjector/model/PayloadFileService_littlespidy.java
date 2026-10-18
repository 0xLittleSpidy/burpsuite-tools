// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Utility service providing file import, deduplication with safe backups,
 * and clipboard copy operations for parameter-based payloads.
 *
 * @author littlespidy
 */
public class PayloadFileService_littlespidy {

    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    /**
     * Imports payloads from a .txt file.
     * Each non-empty line becomes a separate payload entry.
     * Meaningful whitespace and special characters are preserved without trimming.
     * Source metadata is recorded with sourceType = "Imported" and sourceFile = filename.
     */
    public static List<ParamPayloadEntry> importPayloadsFromTxt(File file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("No file provided for import.");
        }
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("File does not exist or is not a regular file: " + file.getAbsolutePath());
        }
        String fileName = file.getName();
        if (!fileName.toLowerCase().endsWith(".txt")) {
            throw new IllegalArgumentException("Invalid file type. Only .txt files are supported.");
        }
        if (file.length() == 0) {
            throw new IllegalArgumentException("The selected file is empty: " + fileName);
        }

        List<ParamPayloadEntry> importedEntries = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                // Skip completely empty or blank lines
                if (line.isEmpty() || line.isBlank()) {
                    continue;
                }

                // Preserve original payload content without unintended modifications
                String payloadValue = line;
                String displayName = payloadValue.length() > 80 ? payloadValue.substring(0, 77) + "..." : payloadValue;
                String id = UUID.randomUUID().toString();

                ParamPayloadEntry entry = new ParamPayloadEntry(
                        id,
                        displayName,
                        payloadValue,
                        "",
                        true,
                        "Imported",
                        fileName
                );
                importedEntries.add(entry);
            }
        }

        if (importedEntries.isEmpty()) {
            throw new IllegalArgumentException("No valid non-empty payloads found in file: " + fileName);
        }

        return importedEntries;
    }

    /**
     * Copies all payload templates from the given entries to the system clipboard,
     * one payload per line, without descriptions or metadata.
     */
    public static int copyPayloadsToClipboard(List<ParamPayloadEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return 0;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < entries.size(); i++) {
            sb.append(entries.get(i).getTemplate());
            if (i < entries.size() - 1) {
                sb.append("\n");
            }
        }

        StringSelection selection = new StringSelection(sb.toString());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, selection);

        return entries.size();
    }

    /**
     * Deduplicates the given payload entries using exact template comparison.
     * Retains one instance per unique payload, preserving the order of the first occurrence.
     * If an entry with description exists, it is retained over an entry without description.
     * If multiple duplicates have descriptions, the earliest entry with description is retained.
     *
     * If duplicates are removed, both the removed entries and the deduplicated list
     * are safely written to backup files on disk before returning.
     */
    public static DeduplicationResult_littlespidy deduplicate(List<ParamPayloadEntry> originalEntries,
                                                               Path backupDirectory,
                                                               String categoryName) throws IOException {
        if (originalEntries == null || originalEntries.isEmpty()) {
            return new DeduplicationResult_littlespidy(
                    new ArrayList<>(),
                    new ArrayList<>(),
                    null,
                    null,
                    0,
                    0
            );
        }

        // Group entries by payload template while preserving first appearance order
        Map<String, List<ParamPayloadEntry>> grouped = new LinkedHashMap<>();
        for (ParamPayloadEntry entry : originalEntries) {
            grouped.computeIfAbsent(entry.getTemplate(), k -> new ArrayList<>()).add(entry);
        }

        List<ParamPayloadEntry> deduplicatedList = new ArrayList<>();
        List<ParamPayloadEntry> removedDuplicates = new ArrayList<>();

        for (Map.Entry<String, List<ParamPayloadEntry>> entryGroup : grouped.entrySet()) {
            List<ParamPayloadEntry> group = entryGroup.getValue();
            if (group.size() == 1) {
                deduplicatedList.add(group.get(0));
            } else {
                // Find entry to retain:
                // Rule 1: If an entry has a non-empty description, prefer it over an entry without description.
                // Rule 2: If multiple entries have descriptions, retain the first one with a description.
                // Rule 3: If none have descriptions, retain the first entry.
                ParamPayloadEntry keptEntry = null;
                for (ParamPayloadEntry candidate : group) {
                    if (candidate.getDescription() != null && !candidate.getDescription().isBlank()) {
                        keptEntry = candidate;
                        break;
                    }
                }
                if (keptEntry == null) {
                    keptEntry = group.get(0);
                }

                // Merge distinct source types and source files across the duplicate group
                java.util.LinkedHashSet<String> mergedSources = new java.util.LinkedHashSet<>();
                java.util.LinkedHashSet<String> mergedFiles = new java.util.LinkedHashSet<>();
                for (ParamPayloadEntry item : group) {
                    if (item.getSourceType() != null && !item.getSourceType().isBlank()) {
                        for (String s : item.getSourceType().split(",")) {
                            if (!s.trim().isEmpty()) mergedSources.add(s.trim());
                        }
                    }
                    if (item.getSourceFile() != null && !item.getSourceFile().isBlank() && !"N/A".equalsIgnoreCase(item.getSourceFile().trim())) {
                        for (String f : item.getSourceFile().split(",")) {
                            if (!f.trim().isEmpty()) mergedFiles.add(f.trim());
                        }
                    }
                }
                if (!mergedSources.isEmpty()) {
                    keptEntry.setSourceType(String.join(", ", mergedSources));
                }
                if (!mergedFiles.isEmpty()) {
                    keptEntry.setSourceFile(String.join(", ", mergedFiles));
                }

                deduplicatedList.add(keptEntry);

                // Add all others to removed duplicates list
                for (ParamPayloadEntry item : group) {
                    if (item != keptEntry) {
                        removedDuplicates.add(item);
                    }
                }
            }
        }

        Path removedFilePath = null;
        Path deduplicatedFilePath = null;

        // If duplicates were found, safely save both lists to disk before returning
        if (!removedDuplicates.isEmpty()) {
            if (backupDirectory == null) {
                backupDirectory = Path.of(".");
            }
            if (!Files.exists(backupDirectory)) {
                Files.createDirectories(backupDirectory);
            }

            String safeCategory = (categoryName != null && !categoryName.isBlank())
                    ? categoryName.toLowerCase().replaceAll("[^a-z0-9_-]", "_")
                    : "payloads";
            String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);

            String removedFileName = safeCategory + "_removed_duplicates_" + timestamp + "_littlespidy.json";
            String deduplicatedFileName = safeCategory + "_deduplicated_payloads_" + timestamp + "_littlespidy.json";

            removedFilePath = backupDirectory.resolve(removedFileName);
            deduplicatedFilePath = backupDirectory.resolve(deduplicatedFileName);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            // 1. Write removed duplicates file
            String removedJson = gson.toJson(removedDuplicates);
            Files.writeString(removedFilePath, removedJson, StandardCharsets.UTF_8);
            if (!Files.exists(removedFilePath) || Files.size(removedFilePath) == 0) {
                throw new IOException("Failed to verify removed duplicates file: " + removedFilePath);
            }

            // 2. Write deduplicated list file
            String deduplicatedJson = gson.toJson(deduplicatedList);
            Files.writeString(deduplicatedFilePath, deduplicatedJson, StandardCharsets.UTF_8);
            if (!Files.exists(deduplicatedFilePath) || Files.size(deduplicatedFilePath) == 0) {
                throw new IOException("Failed to verify deduplicated payload file: " + deduplicatedFilePath);
            }
        }

        return new DeduplicationResult_littlespidy(
                deduplicatedList,
                removedDuplicates,
                removedFilePath,
                deduplicatedFilePath,
                removedDuplicates.size(),
                deduplicatedList.size()
        );
    }

    /**
     * Result container for deduplication operations.
     */
    public record DeduplicationResult_littlespidy(
            List<ParamPayloadEntry> deduplicatedList,
            List<ParamPayloadEntry> removedDuplicates,
            Path removedFilePath,
            Path deduplicatedFilePath,
            int removedCount,
            int remainingCount
    ) {
    }
}
