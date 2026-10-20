// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.storage;

import java.util.ArrayList;
import java.util.List;

/**
 * Data transfer objects for persistent storage of SSO Inspector state.
 */
public class SSOSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<OAuthEntryDTO> entries = new ArrayList<>();
    }

    public static class OAuthEntryDTO {
        public int id;
        public String timestamp;
        public String method;
        public String host;
        public String path;
        public String url;
        public int statusCode;
        public String flowType;

        // Base64 HTTP Preservation
        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;

        public List<OAuthParamDTO> parameters = new ArrayList<>();
        public List<SSOAuditIssueDTO> issues = new ArrayList<>();
    }

    public static class OAuthParamDTO {
        public String name;
        public String rawValue;
        public String decodedValue;
        public String location;
        public String description;
        public boolean standard;
        public boolean sensitive;
    }

    public static class SSOAuditIssueDTO {
        public String title;
        public String severity;
        public String confidence;
        public String description;
        public String remediation;
        public String references;
        public boolean activeProbe;

        public boolean hasIssueMessage;
        public String issueRequestBase64;
        public String issueResponseBase64;
        public String issueHost;
        public int issuePort;
        public boolean issueSecure;
    }
}
