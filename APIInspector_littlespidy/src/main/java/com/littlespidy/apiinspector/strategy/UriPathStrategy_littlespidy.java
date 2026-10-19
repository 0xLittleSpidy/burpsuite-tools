// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.strategy;

import com.littlespidy.apiinspector.model.ProbeMutation_littlespidy;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strategy for discovering API versions embedded directly within the URI path.
 */
public class UriPathStrategy_littlespidy implements VersionStrategy_littlespidy {

    private static final Pattern VERSION_SEGMENT_PATTERN = Pattern.compile(
            "/(v\\d+(?:\\.\\d+)?(?:[a-zA-Z0-9_\\-\\.]*)?|version/(?:v?\\d+(?:\\.\\d+)?)|\\d+\\.\\d+)(/|$)",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SUFFIX_VERSION_PATTERN = Pattern.compile(
            "([_\\-]v?\\d+(?:\\.\\d+)?)(?=\\.[a-zA-Z0-9]+|$)",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public String getName() {
        return "URI Path";
    }

    @Override
    public List<ProbeMutation_littlespidy> generateMutations(HttpRequest baselineRequest, List<String> candidateVersions) {
        List<ProbeMutation_littlespidy> mutations = new ArrayList<>();
        Set<String> seenPaths = new HashSet<>();

        String originalPath = baselineRequest.path();
        if (originalPath == null || originalPath.isEmpty()) {
            originalPath = "/";
        }

        // Split query and path if present in path()
        String pathOnly = originalPath;
        String querySuffix = "";
        int queryIdx = originalPath.indexOf('?');
        if (queryIdx != -1) {
            pathOnly = originalPath.substring(0, queryIdx);
            querySuffix = originalPath.substring(queryIdx);
        }

        seenPaths.add(originalPath);

        Matcher segmentMatcher = VERSION_SEGMENT_PATTERN.matcher(pathOnly);
        boolean foundSegment = segmentMatcher.find();

        Matcher suffixMatcher = SUFFIX_VERSION_PATTERN.matcher(pathOnly);
        boolean foundSuffix = suffixMatcher.find();

        if (foundSegment) {
            String matchedGroup = segmentMatcher.group(1);
            boolean hadVPrefix = matchedGroup.toLowerCase().startsWith("v");

            for (String cand : candidateVersions) {
                String cleanCand = cand.trim();
                if (cleanCand.isEmpty()) continue;

                String candidateSegment = cleanCand;
                if (hadVPrefix && !candidateSegment.toLowerCase().startsWith("v")) {
                    candidateSegment = "v" + candidateSegment;
                }

                String newPathOnly = pathOnly.substring(0, segmentMatcher.start(1))
                        + candidateSegment
                        + pathOnly.substring(segmentMatcher.end(1));

                String newFullPath = newPathOnly + querySuffix;
                if (seenPaths.add(newFullPath)) {
                    HttpRequest mutated = baselineRequest.withPath(newFullPath);
                    mutations.add(new ProbeMutation_littlespidy(
                            getName(),
                            "Path replacement: " + newPathOnly,
                            mutated
                    ));
                }
            }
        } else if (foundSuffix) {
            String matchedSuffix = suffixMatcher.group(1);
            boolean hadV = matchedSuffix.toLowerCase().contains("v");
            char separator = matchedSuffix.charAt(0);

            for (String cand : candidateVersions) {
                String cleanCand = cand.trim();
                if (cleanCand.isEmpty()) continue;

                String formattedCand = (hadV && !cleanCand.toLowerCase().startsWith("v")) ? "v" + cleanCand : cleanCand;
                String newSuffix = separator + formattedCand;

                String newPathOnly = pathOnly.substring(0, suffixMatcher.start(1))
                        + newSuffix
                        + pathOnly.substring(suffixMatcher.end(1));

                String newFullPath = newPathOnly + querySuffix;
                if (seenPaths.add(newFullPath)) {
                    HttpRequest mutated = baselineRequest.withPath(newFullPath);
                    mutations.add(new ProbeMutation_littlespidy(
                            getName(),
                            "Suffix replacement: " + newPathOnly,
                            mutated
                    ));
                }
            }
        } else {
            // No explicit version token found: try inserting version segments
            for (String cand : candidateVersions) {
                String cleanCand = cand.trim();
                if (cleanCand.isEmpty()) continue;

                String versionToken = cleanCand.toLowerCase().startsWith("v") ? cleanCand : "v" + cleanCand;

                // Pattern A: If starts with /api/, insert after /api/ -> /api/{version}/...
                if (pathOnly.startsWith("/api/")) {
                    String newPathOnly = "/api/" + versionToken + pathOnly.substring(4);
                    String newFullPath = newPathOnly + querySuffix;
                    if (seenPaths.add(newFullPath)) {
                        HttpRequest mutated = baselineRequest.withPath(newFullPath);
                        mutations.add(new ProbeMutation_littlespidy(
                                getName(),
                                "Path insertion: " + newPathOnly,
                                mutated
                        ));
                    }
                } else if (pathOnly.startsWith("/")) {
                    // Pattern B: Insert at root / -> /{version}/...
                    String newPathOnly = "/" + versionToken + pathOnly;
                    String newFullPath = newPathOnly + querySuffix;
                    if (seenPaths.add(newFullPath)) {
                        HttpRequest mutated = baselineRequest.withPath(newFullPath);
                        mutations.add(new ProbeMutation_littlespidy(
                                getName(),
                                "Path insertion: " + newPathOnly,
                                mutated
                        ));
                    }
                }
            }
        }

        return mutations;
    }
}
