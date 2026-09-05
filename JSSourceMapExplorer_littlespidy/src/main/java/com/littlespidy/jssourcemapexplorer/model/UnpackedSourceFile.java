// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

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
    List<DiscoveredDependency> dependencies
) {}
