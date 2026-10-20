// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.inputvalidationfuzzer.storage;

import java.util.ArrayList;
import java.util.List;

/**
 * Data transfer objects for persistent storage of Input Validation Fuzzer state.
 */
public class FuzzerSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<TrafficCandidateDTO> sweepCandidates = new ArrayList<>();
        public List<FuzzingSessionDTO> sessions = new ArrayList<>();
    }

    public static class TrafficCandidateDTO {
        public int id;
        public String method;
        public String url;
        public String host;
        public String path;
        public int statusCode;
        public int contentLength;
        public String contentType;
        public int parameterCount;
        public List<String> parameterNames = new ArrayList<>();
        public boolean isAuthenticated;
        public String authIndicator;
        public String dedupeKey;

        // Base64 HTTP Preservation
        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;

        public String timestamp;
    }

    public static class FuzzingSessionDTO {
        public String title;
        public List<TrafficCandidateDTO> targets = new ArrayList<>();
        public List<ConfiguredHeaderDTO> customHeaders = new ArrayList<>();
        public List<FuzzResultDTO> results = new ArrayList<>();
    }

    public static class ConfiguredHeaderDTO {
        public String name;
        public String value;
    }

    public static class FuzzResultDTO {
        public int id;
        public String parameterName;
        public String parameterType;
        public String payloadName;
        public String payloadValue;
        public int baseStatus;
        public int baseLength;
        public int responseStatus;
        public int responseLength;
        public String responseContentType;
        public String signal;
        public String issueSeverity;
        public String evidence;

        // Mutated request & response
        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;

        // Base request & response
        public boolean hasBaseRequest;
        public String baseRequestBase64;
        public String baseRequestHost;
        public int baseRequestPort;
        public boolean baseRequestSecure;

        public boolean hasBaseResponse;
        public String baseResponseBase64;

        public String timestamp;
    }
}
