// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import java.util.*;

/**
 * Reconstructed source project tree holding all extracted source files,
 * aggregated endpoints, secrets, cloud URLs, and dependencies.
 *
 * @author littlespidy
 */
public class UnpackedProject {
    private final String sourceMapUrl;
    private final Map<String, UnpackedSourceFile> filesByPath = new LinkedHashMap<>();
    private final List<DiscoveredSecret> allSecrets = new ArrayList<>();
    private final List<DiscoveredEndpoint> allEndpoints = new ArrayList<>();
    private final List<DiscoveredCloudUrl> allCloudUrls = new ArrayList<>();
    private final List<DiscoveredDependency> allDependencies = new ArrayList<>();

    public UnpackedProject(String sourceMapUrl) {
        this.sourceMapUrl = sourceMapUrl;
    }

    public String getSourceMapUrl() {
        return sourceMapUrl;
    }

    public synchronized void addFile(UnpackedSourceFile file) {
        filesByPath.put(file.relativePath(), file);
        if (file.secrets() != null) {
            allSecrets.addAll(file.secrets());
        }
        if (file.endpoints() != null) {
            allEndpoints.addAll(file.endpoints());
        }
        if (file.cloudUrls() != null) {
            allCloudUrls.addAll(file.cloudUrls());
        }
        if (file.dependencies() != null) {
            allDependencies.addAll(file.dependencies());
        }
    }

    public synchronized Map<String, UnpackedSourceFile> getFilesByPath() {
        return Collections.unmodifiableMap(filesByPath);
    }

    public synchronized UnpackedSourceFile getFile(String path) {
        return filesByPath.get(path);
    }

    public synchronized List<DiscoveredSecret> getAllSecrets() {
        return Collections.unmodifiableList(allSecrets);
    }

    public synchronized List<DiscoveredEndpoint> getAllEndpoints() {
        return Collections.unmodifiableList(allEndpoints);
    }

    public synchronized List<DiscoveredCloudUrl> getAllCloudUrls() {
        return Collections.unmodifiableList(allCloudUrls);
    }

    public synchronized List<DiscoveredDependency> getAllDependencies() {
        return Collections.unmodifiableList(allDependencies);
    }

    public synchronized int getTotalFiles() {
        return filesByPath.size();
    }

    public synchronized int getTotalLines() {
        int lines = 0;
        for (UnpackedSourceFile f : filesByPath.values()) {
            lines += f.lineCount();
        }
        return lines;
    }
}
