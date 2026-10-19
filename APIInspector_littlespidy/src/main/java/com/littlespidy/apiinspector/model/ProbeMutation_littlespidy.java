// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Represents a generated mutation ready to be sent against the target API.
 */
public class ProbeMutation_littlespidy {
    private final String strategyName;
    private final String variationDescription;
    private final HttpRequest request;

    public ProbeMutation_littlespidy(String strategyName, String variationDescription, HttpRequest request) {
        this.strategyName = strategyName;
        this.variationDescription = variationDescription;
        this.request = request;
    }

    public String getStrategyName() {
        return strategyName;
    }

    public String getVariationDescription() {
        return variationDescription;
    }

    public HttpRequest getRequest() {
        return request;
    }
}
