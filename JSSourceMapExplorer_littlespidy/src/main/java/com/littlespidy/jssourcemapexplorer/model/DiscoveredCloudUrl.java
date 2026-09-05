// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Represents a cloud storage, CDN, or object bucket URL (AWS S3, Google Cloud,
 * Azure Blob, Firebase, DigitalOcean, etc.) discovered in JavaScript or Source Maps.
 *
 * @author littlespidy
 */
public record DiscoveredCloudUrl(
    String sourceLocation,
    String sourceType,
    String cloudProvider,   // AWS, Azure, Google Cloud, Firebase, DigitalOcean, etc.
    String cloudUrl,        // e.g. mybucket.s3.amazonaws.com
    int line,
    String contextSnippet
) {}
