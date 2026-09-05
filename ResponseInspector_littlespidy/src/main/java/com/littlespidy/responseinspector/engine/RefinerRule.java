// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Two-stage regular expression rule implementing the "Refiner Regex" technique
 * from sensitive-discoverer.
 * 
 * First matches an anchor suffix or pattern (e.g. "s3.amazonaws.com"), then scans
 * a backward look-back window (default 64 chars) with a refiner regex (e.g. "[a-z0-9\\-]{3,63}\\.$")
 * to capture bucket/client prefixes without catastrophic regex backtracking.
 */
public record RefinerRule(
        String name,
        Pattern primaryPattern,
        Pattern refinerPattern,
        int lookbackWindow,
        boolean requireRefinerMatch,
        boolean maskMatch
) {
    public record MatchResult(String value, int startOffset, int endOffset) {}

    public static RefinerRule ofRefined(String name, String primaryRegex, String refinerRegex, boolean requireRefiner, boolean mask) {
        return new RefinerRule(
                name,
                Pattern.compile(primaryRegex),
                refinerRegex != null ? Pattern.compile(refinerRegex) : null,
                64,
                requireRefiner,
                mask
        );
    }

    public static RefinerRule ofSimple(String name, String primaryRegex, boolean mask) {
        return new RefinerRule(
                name,
                Pattern.compile(primaryRegex),
                null,
                0,
                false,
                mask
        );
    }

    public List<MatchResult> findMatches(String content) {
        List<MatchResult> results = new ArrayList<>();
        if (content == null || content.isEmpty()) {
            return results;
        }

        Matcher matcher = primaryPattern.matcher(content);
        while (matcher.find()) {
            String match = matcher.group();
            int start = matcher.start();
            int end = matcher.end();

            if (refinerPattern != null) {
                int window = lookbackWindow > 0 ? lookbackWindow : 64;
                int regionStart = Math.max(0, start - window);
                Matcher pre = refinerPattern.matcher(content);
                pre.region(regionStart, start);
                if (pre.find()) {
                    match = pre.group() + match;
                    start = pre.start();
                } else if (requireRefinerMatch) {
                    continue; // Skip if refiner prefix is required but absent
                }
            }

            results.add(new MatchResult(match, start, end));
        }

        return results;
    }
}
