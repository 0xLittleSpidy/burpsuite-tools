// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.storage;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Data transfer objects for persistent storage of Header Inspector state.
 */
public class HeaderSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<CacheEntryDTO> cacheEntries = new ArrayList<>();
        public List<CSPEntryDTO> cspEntries = new ArrayList<>();
        public List<HSTSEntryDTO> hstsEntries = new ArrayList<>();
    }

    public static class CacheEntryDTO {
        public int id;
        public String url;
        public String host;
        public String path;
        public String method;
        public int statusCode;
        public String contentType;
        public String cacheControl;
        public String pragma;
        public String expires;
        public String age;
        public String etag;
        public String lastModified;
        public String vary;
        public String xCache;
        public String xCacheHits;
        public String cdnCacheControl;
        public String surrogateControl;
        public String cfCacheStatus;
        public String timestamp;

        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;
    }

    public static class CSPEntryDTO {
        public int id;
        public String url;
        public String host;
        public String path;
        public String method;
        public int statusCode;
        public String contentType;
        public String cspHeader;
        public String cspReportOnlyHeader;
        public String xCspHeader;
        public String xWebKitCspHeader;
        public Map<String, List<String>> parsedDirectives;
        public String timestamp;

        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;
    }

    public static class HSTSEntryDTO {
        public int id;
        public String url;
        public String host;
        public String path;
        public String method;
        public int statusCode;
        public String contentType;
        public String rawHeader;
        public long maxAge;
        public boolean includeSubDomains;
        public boolean preload;
        public String assessment;
        public String timestamp;

        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;
    }
}
