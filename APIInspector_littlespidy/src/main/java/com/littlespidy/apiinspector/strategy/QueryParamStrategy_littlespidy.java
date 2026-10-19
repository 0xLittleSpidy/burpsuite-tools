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
 * Strategy for discovering API versions passed via URL query parameters.
 */
public class QueryParamStrategy_littlespidy implements VersionStrategy_littlespidy {

    private static final String[] TARGET_PARAMS = {
            "version",
            "v",
            "api_version",
            "api-version",
            "apiVersion",
            "ver",
            "v_num"
    };

    @Override
    public String getName() {
        return "Query Parameter";
    }

    @Override
    public List<ProbeMutation_littlespidy> generateMutations(HttpRequest baselineRequest, List<String> candidateVersions) {
        List<ProbeMutation_littlespidy> mutations = new ArrayList<>();
        Set<String> seenPaths = new HashSet<>();

        String originalPath = baselineRequest.path();
        if (originalPath == null || originalPath.isEmpty()) {
            originalPath = "/";
        }
        seenPaths.add(originalPath);

        for (String paramName : TARGET_PARAMS) {
            Pattern paramPattern = Pattern.compile("([?&])" + Pattern.quote(paramName) + "=([^&#]*)", Pattern.CASE_INSENSITIVE);
            Matcher matcher = paramPattern.matcher(originalPath);
            boolean hasParam = matcher.find();

            for (String cand : candidateVersions) {
                String cleanCand = cand.trim();
                if (cleanCand.isEmpty()) continue;

                List<String> valuesToTest = new ArrayList<>();
                valuesToTest.add(cleanCand);
                if (cleanCand.startsWith("v") || cleanCand.startsWith("V")) {
                    valuesToTest.add(cleanCand.substring(1));
                }

                for (String val : valuesToTest) {
                    String newPath;
                    if (hasParam) {
                        // Replace existing parameter value
                        String existingVal = matcher.group(2);
                        if (existingVal.equalsIgnoreCase(val)) {
                            continue; // Skip identical to baseline
                        }
                        newPath = matcher.replaceFirst("$1" + paramName + "=" + val);
                    } else {
                        // Append new parameter
                        char delimiter = originalPath.contains("?") ? '&' : '?';
                        newPath = originalPath + delimiter + paramName + "=" + val;
                    }

                    if (seenPaths.add(newPath)) {
                        HttpRequest mutated = baselineRequest.withPath(newPath);
                        mutations.add(new ProbeMutation_littlespidy(
                                getName(),
                                "?" + paramName + "=" + val,
                                mutated
                        ));
                    }
                }
            }
        }

        return mutations;
    }
}
