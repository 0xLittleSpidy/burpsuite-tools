// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.storage;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Data transfer objects for persistent storage of Payload Injector state.
 * Plain ASCII text only.
 */
public class PayloadInjectorSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;

        // Settings
        public String injectionMode = "Replace parameter value";
        public String encodingMode = "Auto (URL encode Query/Body, Raw for JSON)";
        public boolean targetUrlParams = true;
        public boolean targetBodyParams = true;
        public boolean targetJsonParams = true;
        public boolean targetCookieParams = false;

        // Payloads by category name
        public Map<String, List<ParamPayloadDTO>> paramPayloads = new LinkedHashMap<>();

        // Smuggling payloads
        public List<SmugglingPayloadDTO> smugglingPayloads = new ArrayList<>();

        // File path payloads
        public List<FilePathDTO> linuxFilePaths = new ArrayList<>();
        public List<FilePathDTO> windowsFilePaths = new ArrayList<>();
    }

    public static class ParamPayloadDTO {
        public String id;
        public String name;
        public String template;
        public String description;
        public boolean enabled;
        public String sourceType;
        public String sourceFile;
        public String platform;
    }

    public static class SmugglingPayloadDTO {
        public String name;
        public String description;
        public Map<String, String> headers = new LinkedHashMap<>();
        public String body;
        public String sourceType;
        public String sourceFile;
    }

    public static class FilePathDTO {
        public String id;
        public String path;
        public String category;
        public String description;
        public String platform;
        public boolean enabled;
        public String sourceType;
        public String sourceFile;
    }
}
