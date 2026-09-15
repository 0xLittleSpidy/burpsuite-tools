// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import java.util.Collections;
import java.util.List;

/**
 * Represents an individual original source file extracted from an unpacked Source Map.
 *
 * @author littlespidy
 */
public record UnpackedSourceFile(
    String relativePath,
    String fileName,
    String content,
    int lineCount,
    int sizeBytes,
    List<DiscoveredSecret> secrets,
    List<DiscoveredEndpoint> endpoints,
    List<DiscoveredCloudUrl> cloudUrls,
    List<DiscoveredDependency> dependencies,
    List<DiscoveredComment> comments,
    List<DiscoveredSecurityBypass> securityBypasses
) {
    public UnpackedSourceFile(
        String relativePath,
        String fileName,
        String content,
        int lineCount,
        int sizeBytes,
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints,
        List<DiscoveredCloudUrl> cloudUrls,
        List<DiscoveredDependency> dependencies,
        List<DiscoveredComment> comments
    ) {
        this(relativePath, fileName, content, lineCount, sizeBytes, secrets, endpoints, cloudUrls, dependencies, comments, Collections.emptyList());
    }

    public UnpackedSourceFile(
        String relativePath,
        String fileName,
        String content,
        int lineCount,
        int sizeBytes,
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints,
        List<DiscoveredCloudUrl> cloudUrls,
        List<DiscoveredDependency> dependencies
    ) {
        this(relativePath, fileName, content, lineCount, sizeBytes, secrets, endpoints, cloudUrls, dependencies, Collections.emptyList(), Collections.emptyList());
    }
}
