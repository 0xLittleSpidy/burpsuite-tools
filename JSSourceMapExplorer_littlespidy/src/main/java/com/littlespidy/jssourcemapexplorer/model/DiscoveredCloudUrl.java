// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a cloud storage, CDN, or object bucket URL (AWS S3, Google Cloud,
 * Azure Blob, Firebase, DigitalOcean, etc.) discovered in JavaScript or Source Maps.
 *
 * <p>Includes start and end character offsets for deep-linking quad navigation.
 *
 * @author littlespidy
 */
public record DiscoveredCloudUrl(
    String sourceLocation,
    String sourceType,
    String cloudProvider,   // AWS, Azure, Google Cloud, Firebase, DigitalOcean, etc.
    String cloudUrl,        // e.g. mybucket.s3.amazonaws.com
    int line,
    int startOffset,
    int endOffset,
    String contextSnippet
) {
    public DiscoveredCloudUrl(
        String sourceLocation,
        String sourceType,
        String cloudProvider,
        String cloudUrl,
        int line,
        String contextSnippet
    ) {
        this(sourceLocation, sourceType, cloudProvider, cloudUrl, line, 0, 0, contextSnippet);
    }
}
