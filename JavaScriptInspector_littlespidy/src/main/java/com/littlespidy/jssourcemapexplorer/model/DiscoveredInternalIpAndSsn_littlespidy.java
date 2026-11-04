// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import java.util.Objects;

/**
 * Represents a discovered Internal IP Address (RFC 1918, Loopback, Link-Local, IPv6 Unique Local)
 * or Social Security Number (SSN) detected in JavaScript assets or unpacked Source Maps.
 *
 * @author littlespidy
 */
public record DiscoveredInternalIpAndSsn_littlespidy(
    String sourceLocation,
    String sourceType,
    String findingType, // "Internal IP Address" or "Social Security Number (SSN)"
    String matchValue,
    String subtype,     // e.g. "RFC 1918 (10.x)", "RFC 1918 (172.16-31.x)", "RFC 1918 (192.168.x)", "Loopback (127.x)", "Link-Local / Carrier NAT", "IPv6 Unique Local", "SSN (Standard Formatted)", "SSN (Key-Value)"
    int line,
    int startOffset,
    int endOffset,
    String contextSnippet,
    String classification // "Not Classified", "True Positive", "False Positive"
) {
    public DiscoveredInternalIpAndSsn_littlespidy(
        String sourceLocation,
        String sourceType,
        String findingType,
        String matchValue,
        String subtype,
        int line,
        int startOffset,
        int endOffset,
        String contextSnippet
    ) {
        this(sourceLocation, sourceType, findingType, matchValue, subtype, line, startOffset, endOffset, contextSnippet, "Not Classified");
    }

    public DiscoveredInternalIpAndSsn_littlespidy withClassification(String newClass) {
        return new DiscoveredInternalIpAndSsn_littlespidy(
            sourceLocation,
            sourceType,
            findingType,
            matchValue,
            subtype,
            line,
            startOffset,
            endOffset,
            contextSnippet,
            newClass != null ? newClass : "Not Classified"
        );
    }
}
