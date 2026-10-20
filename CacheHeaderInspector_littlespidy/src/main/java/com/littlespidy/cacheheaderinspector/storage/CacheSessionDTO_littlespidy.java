// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.storage;

import java.util.ArrayList;
import java.util.List;

/**
 * Data transfer objects for persistent storage of Cache Header Inspector state.
 */
public class CacheSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<CacheEntryDTO> entries = new ArrayList<>();
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

        // Base64 HTTP Preservation
        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;
    }
}
