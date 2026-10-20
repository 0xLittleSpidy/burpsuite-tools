// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector.storage;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Data transfer objects for persistent storage of CSP Inspector state.
 */
public class CSPSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<CSPEntryDTO> entries = new ArrayList<>();
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
