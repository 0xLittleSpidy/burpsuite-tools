// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.storage;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Data Transfer Objects for JSON serialization and deserialization of
 * Response Inspector session state.
 */
public class SessionStateDTO_littlespidy {

    public static class SessionRootDTO {
        public int formatVersion = 1;
        public String savedAt;
        public String sessionName;
        public PasswordsConfigDTO passwordsConfig = new PasswordsConfigDTO();
        public List<DomainEntryDTO> inScopeDomains = new ArrayList<>();
        public Map<String, String> secretTypeClassifications = new LinkedHashMap<>();
        public List<FindingEntryDTO> findings = new ArrayList<>();
    }

    public static class PasswordsConfigDTO {
        public boolean caseSensitive = false;
        public List<String> passwords = new ArrayList<>();
    }

    public static class DomainEntryDTO {
        public String domain;
        public boolean selected = true;
        public int findingCount = 0;

        public DomainEntryDTO() {}

        public DomainEntryDTO(String domain, boolean selected, int findingCount) {
            this.domain = domain;
            this.selected = selected;
            this.findingCount = findingCount;
        }
    }

    public static class FindingEntryDTO {
        public int id;
        public String category;
        public String patternName;
        public String matchValue;
        public String matchLocation;
        public String method;
        public String url;
        public String host;
        public String path;
        public short statusCode;
        public String contentType;
        public int contentLength;
        public String timeString;
        public int startOffset;
        public int endOffset;

        // HTTP message serialization
        public boolean hasRequest;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;
        public String requestBase64;

        public boolean hasResponse;
        public String responseBase64;

        // Classification override
        public String individualClassification;
    }
}
