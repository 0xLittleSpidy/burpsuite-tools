// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

/**
 * Data models for tracking reference requests and generated Intruder variations.
 */
public class IntruderStrategyEntry_littlespidy {

    public static class ReferenceRequestEntry {
        private final int id;
        private final long timestamp;
        private final String strategyName;
        private final String method;
        private final String originalPath;
        private final String host;
        private final String fullUrl;
        private final HttpRequest referenceRequest;
        private final List<GeneratedVariationItem> variations;

        public ReferenceRequestEntry(
                int id,
                long timestamp,
                String strategyName,
                String method,
                String originalPath,
                String host,
                String fullUrl,
                HttpRequest referenceRequest,
                List<GeneratedVariationItem> variations) {
            this.id = id;
            this.timestamp = timestamp;
            this.strategyName = strategyName;
            this.method = method;
            this.originalPath = originalPath;
            this.host = host;
            this.fullUrl = fullUrl;
            this.referenceRequest = referenceRequest;
            this.variations = variations != null ? variations : new ArrayList<>();
        }

        public int getId() { return id; }
        public long getTimestamp() { return timestamp; }
        public String getStrategyName() { return strategyName; }
        public String getMethod() { return method; }
        public String getOriginalPath() { return originalPath; }
        public String getHost() { return host; }
        public String getFullUrl() { return fullUrl; }
        public HttpRequest getReferenceRequest() { return referenceRequest; }
        public List<GeneratedVariationItem> getVariations() { return variations; }
    }

    public static class GeneratedVariationItem {
        private final int variationIndex;
        private final String pathVariation;
        private final boolean authenticated;
        private final String intruderStatus;
        private final String fullUrl;
        private final HttpRequest generatedRequest;

        public GeneratedVariationItem(
                int variationIndex,
                String pathVariation,
                boolean authenticated,
                String intruderStatus,
                String fullUrl,
                HttpRequest generatedRequest) {
            this.variationIndex = variationIndex;
            this.pathVariation = pathVariation;
            this.authenticated = authenticated;
            this.intruderStatus = intruderStatus;
            this.fullUrl = fullUrl;
            this.generatedRequest = generatedRequest;
        }

        public int getVariationIndex() { return variationIndex; }
        public String getPathVariation() { return pathVariation; }
        public boolean isAuthenticated() { return authenticated; }
        public String getIntruderStatus() { return intruderStatus; }
        public String getFullUrl() { return fullUrl; }
        public HttpRequest getGeneratedRequest() { return generatedRequest; }
    }
}
