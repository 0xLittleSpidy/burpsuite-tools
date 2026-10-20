// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.storage;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Data transfer objects for persistent storage of Convert POST to GET state.
 */
public class ConvertSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<PostCandidateDTO> sweepCandidates = new ArrayList<>();
        public List<ConvertSessionDTO> sessions = new ArrayList<>();
    }

    public static class PostCandidateDTO {
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
        public Set<String> parameterTypes = new HashSet<>();
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

    public static class ConvertSessionDTO {
        public String title;
        public List<PostCandidateDTO> targets = new ArrayList<>();
        public List<ConfiguredHeaderDTO> customHeaders = new ArrayList<>();
        public List<ConversionResultDTO> results = new ArrayList<>();
    }

    public static class ConfiguredHeaderDTO {
        public String name;
        public String value;
    }

    public static class ConversionResultDTO {
        public int id;
        public String method;
        public String url;
        public String host;
        public String path;
        public int baseStatus;
        public int baseLength;
        public int getStatus;
        public int getLength;
        public String getContentType;
        public String signal;
        public String severity;
        public String evidence;

        // Original POST Request & Response
        public boolean hasOriginalRequest;
        public String originalRequestBase64;
        public String originalRequestHost;
        public int originalRequestPort;
        public boolean originalRequestSecure;

        public boolean hasOriginalResponse;
        public String originalResponseBase64;

        // Converted GET Request & Response
        public boolean hasConvertedRequest;
        public String convertedRequestBase64;
        public String convertedRequestHost;
        public int convertedRequestPort;
        public boolean convertedRequestSecure;

        public boolean hasConvertedResponse;
        public String convertedResponseBase64;

        public String timestamp;
    }
}
