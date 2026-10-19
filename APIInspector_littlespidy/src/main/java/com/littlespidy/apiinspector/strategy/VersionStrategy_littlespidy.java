// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.strategy;

import com.littlespidy.apiinspector.model.ProbeMutation_littlespidy;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

/**
 * Interface for API version detection and mutation strategies.
 */
public interface VersionStrategy_littlespidy {
    /**
     * Human-readable name of the strategy (ASCII only).
     */
    String getName();

    /**
     * Generates a list of mutated requests based on candidate versions.
     */
    List<ProbeMutation_littlespidy> generateMutations(HttpRequest baselineRequest, List<String> candidateVersions);
}
