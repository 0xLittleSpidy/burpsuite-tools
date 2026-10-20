// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.uploadscanner.storage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Data transfer objects for persistent storage of Upload Scanner state.
 * Plain ASCII text only.
 */
public class UploadSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<UploadTabSessionDTO> sessions = new ArrayList<>();
    }

    public static class UploadTabSessionDTO {
        public String tabTitle;
        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;

        // Configurations
        public boolean redownloaderEnabled = true;
        public String uploadDirectoryPreset;

        // Attack settings & options
        public Map<String, Boolean> attackOptions = new HashMap<>();
        public String customExtensions = "";
        public int maxFileSizeMB = 20;
        public int throttleMs = 50;

        // Log entries
        public List<UploadLogEntryDTO> logEntries = new ArrayList<>();
    }

    public static class UploadLogEntryDTO {
        public int id;
        public String stage;
        public String method;
        public short statusCode;
        public String payloadName;
        public int responseLength;
        public String url;
        public String extractedMarkerText;
        public long timestamp;

        public boolean hasRequestResponse;
        public String requestBase64;
        public String responseBase64;
        public String host;
        public int port;
        public boolean secure;
    }
}
