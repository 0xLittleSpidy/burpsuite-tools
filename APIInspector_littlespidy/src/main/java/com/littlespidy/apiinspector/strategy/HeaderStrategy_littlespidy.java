// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.strategy;

import com.littlespidy.apiinspector.model.ProbeMutation_littlespidy;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

/**
 * Strategy for discovering API versions via custom and standard request headers.
 */
public class HeaderStrategy_littlespidy implements VersionStrategy_littlespidy {

    private static final String[] TARGET_HEADERS = {
            "X-API-Version",
            "API-Version",
            "X-Version",
            "Version",
            "Accept-Version",
            "X-Accept-Version",
            "App-Version",
            "Client-Version"
    };

    @Override
    public String getName() {
        return "Request Header";
    }

    @Override
    public List<ProbeMutation_littlespidy> generateMutations(HttpRequest baselineRequest, List<String> candidateVersions) {
        List<ProbeMutation_littlespidy> mutations = new ArrayList<>();

        for (String headerName : TARGET_HEADERS) {
            String existingVal = baselineRequest.headerValue(headerName);

            for (String cand : candidateVersions) {
                String cleanCand = cand.trim();
                if (cleanCand.isEmpty()) continue;

                // Also consider raw number vs v-prefixed
                List<String> valuesToTest = new ArrayList<>();
                valuesToTest.add(cleanCand);
                if (cleanCand.startsWith("v") || cleanCand.startsWith("V")) {
                    valuesToTest.add(cleanCand.substring(1));
                }

                for (String val : valuesToTest) {
                    if (existingVal != null && existingVal.equalsIgnoreCase(val)) {
                        continue; // Skip if identical to baseline
                    }

                    HttpRequest mutated = baselineRequest.withHeader(headerName, val);
                    mutations.add(new ProbeMutation_littlespidy(
                            getName(),
                            headerName + ": " + val,
                            mutated
                    ));
                }
            }
        }

        return mutations;
    }
}
