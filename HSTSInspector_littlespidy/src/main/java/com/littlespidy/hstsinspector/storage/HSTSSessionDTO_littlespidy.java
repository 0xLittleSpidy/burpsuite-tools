// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector.storage;

import java.util.ArrayList;
import java.util.List;

/**
 * Data transfer objects for persistent storage of HSTS Inspector state.
 */
public class HSTSSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<HSTSEntryDTO> entries = new ArrayList<>();
    }

    public static class HSTSEntryDTO {
        public int id;
        public String url;
        public String host;
        public String path;
        public String method;
        public int statusCode;
        public String contentType;
        public String hstsHeader;
        public long maxAge;
        public boolean includeSubDomains;
        public boolean preload;
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
