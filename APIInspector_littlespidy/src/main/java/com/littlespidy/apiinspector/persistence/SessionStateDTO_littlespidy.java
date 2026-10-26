// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import java.util.ArrayList;
import java.util.List;

/**
 * Data Transfer Objects for JSON serialization of API Inspector session state.
 */
public class SessionStateDTO_littlespidy {

    public static class SessionRootDTO {
        public int version = 2;
        public long savedAt;
        public List<SessionTabDTO> tabs = new ArrayList<>();
        public List<ReferenceRequestDTO> documentationEntries = new ArrayList<>();
        public List<ReferenceRequestDTO> endpointDiscoveryEntries = new ArrayList<>();
        public List<ImportedCollectionDTO> importedCollections = new ArrayList<>();
        public List<AuthProfileDTO> authProfiles = new ArrayList<>();
        public List<AuthTestResultDTO> authTestResults = new ArrayList<>();
        public List<HiddenEndpointDTO> hiddenEndpoints = new ArrayList<>();
        public SessionStoreDTO sessionStore;
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

    public static class ImportedCollectionDTO {
        public String id;
        public String name;
        public String formatType;
        public String sourceType;
        public String sourceLocation;
        public String targetBaseUrl;
        public String importStatus;
        public String statusMessage;
        public long importedAt;
        public String assignedProfileId;
        public List<DiscoveredEndpointDTO> endpoints = new ArrayList<>();
    }

    public static class DiscoveredEndpointDTO {
        public String id;
        public String method;
        public String path;
        public String summary;
        public String description;
        public java.util.Map<String, String> headers;
        public java.util.Map<String, String> queryParams;
        public java.util.Map<String, String> pathParams;
        public java.util.Map<String, String> bodyParams;
        public java.util.Map<String, String> queryParamTypes;
        public java.util.Map<String, String> pathParamTypes;
        public java.util.Map<String, String> bodyParamTypes;
        public String requestBodySample;
        public String contentType;
        public boolean requiresAuth;
        public List<String> authSchemes;
        public String customRawRequest;
    }

    public static class AuthProfileDTO {
        public String id;
        public String name;
        public String authType;
        public String bearerToken;
        public String apiKeyName;
        public String apiKeyValue;
        public String apiKeyLocation;
        public String basicUsername;
        public String basicPassword;
        public String cookieName;
        public String cookieValue;
        public String customHeaderName;
        public String customHeaderValue;
        public boolean testUnauthenticatedComparison;
    }

    public static class AuthTestResultDTO {
        public String id;
        public String collectionId;
        public String collectionName;
        public String method;
        public String path;
        public String fullUrl;
        public String profileId;
        public String profileName;
        public int authStatusCode;
        public int authResponseLength;
        public long authLatencyMs;
        public int unauthStatusCode;
        public int unauthResponseLength;
        public long unauthLatencyMs;
        public String outcome;
        public String errorMessage;
        public long timestamp;
        public String authRequestBase64;
        public String authResponseBase64;
        public String unauthRequestBase64;
        public String unauthResponseBase64;
    }

    public static class SessionStoreDTO {
        public boolean enabled;
        public String applyMode;
        public String rawHeaders;
        public String bearerToken;
        public java.util.Map<String, String> customHeaders;
        public String cookieName;
        public String cookieValue;
    }

    public static class HiddenEndpointDTO {
        public String id;
        public String source;
        public String method;
        public String url;
        public String path;
        public String parametersSummary;
        public int statusCode;
        public String notes;
        public long discoveredAt;
        public HttpMessageDTO request;
        public HttpMessageDTO response;
    }
}
