// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import java.util.ArrayList;
import java.util.List;

/**
 * Data Transfer Objects for JSON serialization of API Inspector session state.
 */
public class SessionStateDTO_littlespidy {

    public static class SessionRootDTO {
        public int version = 1;
        public long savedAt;
        public List<SessionTabDTO> tabs = new ArrayList<>();
        public List<ReferenceRequestDTO> documentationEntries = new ArrayList<>();
        public List<ReferenceRequestDTO> endpointDiscoveryEntries = new ArrayList<>();
    }

    public static class SessionTabDTO {
        public String tabTitle;
        public String targetUrl;
        public String method;
        public HttpMessageDTO baselineRequest;
        public HttpMessageDTO baselineResponse;
        public StrategyConfigDTO strategies = new StrategyConfigDTO();
        public String candidates;
        public int threads;
        public int delayMs;
        public List<ProbeResultDTO> results = new ArrayList<>();
    }

    public static class StrategyConfigDTO {
        public boolean uriPath = true;
        public boolean headers = true;
        public boolean queryParams = true;
        public boolean contentNegotiation = true;
        public boolean subdomains = false;
        public boolean cookies = false;
    }

    public static class HttpMessageDTO {
        public String host;
        public int port;
        public boolean secure;
        public String base64Bytes;
    }

    public static class ProbeResultDTO {
        public int id;
        public String strategyName;
        public String variation;
        public int statusCode;
        public int responseLength;
        public String mimeType;
        public String diffAnalysis;
        public long latencyMs;
        public HttpMessageDTO request;
        public HttpMessageDTO response;
    }

    public static class ReferenceRequestDTO {
        public int id;
        public long timestamp;
        public String strategyName;
        public String method;
        public String originalPath;
        public String host;
        public String fullUrl;
        public HttpMessageDTO referenceRequest;
        public List<GeneratedVariationDTO> variations = new ArrayList<>();
    }

    public static class GeneratedVariationDTO {
        public int variationIndex;
        public String pathVariation;
        public boolean authenticated;
        public String intruderStatus;
        public String fullUrl;
        public HttpMessageDTO generatedRequest;
    }
}
