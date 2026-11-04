// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.util.*;

/**
 * Parameter and path-parameter differential collapsing engine ported from reKover.
 * Folds query parameter value variants into single representative endpoints,
 * and groups sibling path-parameter routes based on body response similarity (Jaccard).
 *
 * @author littlespidy
 */
public final class ParamDiffCollapser_littlespidy {

    private ParamDiffCollapser_littlespidy() {}

    public interface BodyFetcher {
        String fetchBody(String url);
    }

    /**
     * Collapses a collection of parameterized URLs into representative endpoints.
     */
    public static List<String> collapseAndRank(
        Collection<String> candidateUrls,
        BodyFetcher bodyFetcher,
        int cap,
        int simThreshold
    ) {
        if (candidateUrls == null || candidateUrls.isEmpty()) {
            return Collections.emptyList();
        }

        // 1. Query-collapse: one endpoint per path, heaviest combo as representative
        Map<String, Long> pathWeights = new HashMap<>();
        Map<String, Long> pathBestCount = new HashMap<>();
        Map<String, String> pathBestUrl = new HashMap<>();
        Map<String, Long> sigCounts = new HashMap<>();
        Map<String, String> sigUrls = new HashMap<>();

        for (String url : candidateUrls) {
            if (url == null || url.isBlank()) continue;
            UrlSignature_littlespidy sig = UrlSignature_littlespidy.fromUrl(url);
            String sigStr = sig.signature();
            sigCounts.merge(sigStr, 1L, Long::sum);
            sigUrls.putIfAbsent(sigStr, url);
        }

        for (Map.Entry<String, Long> e : sigCounts.entrySet()) {
            String s = e.getKey();
            long c = e.getValue();
            String p = s.substring(0, s.indexOf("::"));
            pathWeights.merge(p, c, Long::sum);
            if (c > pathBestCount.getOrDefault(p, 0L)) {
                pathBestCount.put(p, c);
                pathBestUrl.put(p, sigUrls.get(s));
            }
        }

        // 2. Group endpoints by (parent path, param keys) to find path-param siblings
        Map<String, List<String>> groupMembers = new HashMap<>();
        for (String p : pathWeights.keySet()) {
            String bestUrl = pathBestUrl.get(p);
            UrlSignature_littlespidy sig = UrlSignature_littlespidy.fromUrl(bestUrl);
            String keys = sig.paramKeys();
            int lastSlash = p.lastIndexOf('/');
            String parent = (lastSlash > 0) ? p.substring(0, lastSlash) : "/";
            String groupKey = parent + "::" + keys;
            groupMembers.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(p);
        }

        // 3. Path-param collapse via Jaccard similarity if BodyFetcher provided
        Map<String, Long> finalWeights = new HashMap<>();
        Map<String, String> finalUrls = new HashMap<>();

        for (List<String> members : groupMembers.values()) {
            if (members.size() >= 2 && bodyFetcher != null) {
                try {
                    String b1 = bodyFetcher.fetchBody(pathBestUrl.get(members.get(0)));
                    String b2 = bodyFetcher.fetchBody(pathBestUrl.get(members.get(1)));
                    int sim = JaccardSimilarity_littlespidy.calculate(b1, b2);
                    if (sim >= simThreshold) {
                        // Collapse all members to the single heaviest member
                        String best = null;
                        long bw = -1;
                        long tot = 0;
                        for (String m : members) {
                            long w = pathWeights.getOrDefault(m, 0L);
                            tot += w;
                            if (w > bw) {
                                bw = w;
                                best = m;
                            }
                        }
                        if (best != null) {
                            finalWeights.put(best, tot);
                            finalUrls.put(best, pathBestUrl.get(best));
                        }
                        continue;
                    }
                } catch (Exception ignored) {}
            }

            for (String m : members) {
                finalWeights.put(m, pathWeights.get(m));
                finalUrls.put(m, pathBestUrl.get(m));
            }
        }

        // 4. Rank by recurrence and keep top cap
        List<ParetoCut_littlespidy.WeightedItem<String>> weighted = new ArrayList<>();
        for (Map.Entry<String, Long> entry : finalWeights.entrySet()) {
            weighted.add(new ParetoCut_littlespidy.WeightedItem<>(entry.getValue(), finalUrls.get(entry.getKey())));
        }

        return ParetoCut_littlespidy.cut(weighted, cap);
    }
}
