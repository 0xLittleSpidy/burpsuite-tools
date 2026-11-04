// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.net.URI;
import java.util.*;

/**
 * Historical archive differential engine ported from the reKover tool.
 * Diffs Wayback CDX records against live crawled and wordlist paths,
 * isolates archive-only endpoints that are delinked on the live site,
 * ranks them by capture recurrence using Pareto cut (vital few), and yields candidates for live-probing.
 *
 * @author littlespidy
 */
public final class WaybackArchiveDiffer_littlespidy {

    private WaybackArchiveDiffer_littlespidy() {}

    public record ArchiveDiffResult(
        List<String> survivorUrls,
        int totalArchiveRecords,
        int alreadyKnownCount,
        int delinkedUniqueSignatures
    ) {}

    /**
     * Diffs archive records against known live paths and returns prioritized candidate endpoints.
     */
    public static ArchiveDiffResult diffArchive(
        Collection<String> rawCdxLines,
        String targetDomain,
        Set<String> liveKnownUrlsOrPaths,
        int cap
    ) {
        if (rawCdxLines == null || rawCdxLines.isEmpty() || targetDomain == null || targetDomain.isBlank()) {
            return new ArchiveDiffResult(Collections.emptyList(), 0, 0, 0);
        }

        String normDomain = targetDomain.trim().toLowerCase();

        // 1. Build set of signatures for already known live endpoints
        Set<String> knownSignatures = new HashSet<>();
        if (liveKnownUrlsOrPaths != null) {
            for (String live : liveKnownUrlsOrPaths) {
                knownSignatures.add(UrlSignature_littlespidy.fromUrl(live).signature());
            }
        }

        Map<String, Long> signatureCounts = new HashMap<>();
        Map<String, String> signatureExampleUrls = new HashMap<>();
        int alreadyKnown = 0;
        int totalCdx = 0;

        for (String line : rawCdxLines) {
            if (line == null || line.isBlank()) continue;
            totalCdx++;

            String urlStr = line.trim();
            // Handle space-separated CDX format (field 3 usually original URL, or space split)
            if (urlStr.contains(" ")) {
                String[] parts = urlStr.split("\\s+");
                for (String part : parts) {
                    if (part.startsWith("http://") || part.startsWith("https://")) {
                        urlStr = part;
                        break;
                    }
                }
            }

            try {
                if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
                    urlStr = "http://" + urlStr;
                }
                URI uri = URI.create(urlStr);
                String host = uri.getHost();
                if (host == null || !host.toLowerCase().endsWith(normDomain)) {
                    continue;
                }

                UrlSignature_littlespidy sigObj = UrlSignature_littlespidy.fromUrl(urlStr);
                String sig = sigObj.signature();

                if (knownSignatures.contains(sig)) {
                    alreadyKnown++;
                    continue;
                }

                signatureCounts.merge(sig, 1L, Long::sum);
                signatureExampleUrls.putIfAbsent(sig, urlStr);
            } catch (Exception ignored) {}
        }

        if (signatureCounts.isEmpty()) {
            return new ArchiveDiffResult(Collections.emptyList(), totalCdx, alreadyKnown, 0);
        }

        // Apply Pareto cut (top 80% weight, hard capped at cap)
        List<ParetoCut_littlespidy.WeightedItem<String>> weighted = new ArrayList<>();
        for (Map.Entry<String, Long> entry : signatureCounts.entrySet()) {
            String url = signatureExampleUrls.get(entry.getKey());
            if (url != null) {
                weighted.add(new ParetoCut_littlespidy.WeightedItem<>(entry.getValue(), url));
            }
        }

        List<String> survivors = ParetoCut_littlespidy.cut(weighted, cap);
        return new ArchiveDiffResult(survivors, totalCdx, alreadyKnown, signatureCounts.size());
    }
}
