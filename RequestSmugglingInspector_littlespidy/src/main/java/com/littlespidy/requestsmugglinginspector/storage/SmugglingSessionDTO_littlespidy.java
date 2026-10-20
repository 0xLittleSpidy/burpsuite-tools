// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.storage;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Data transfer objects for persistent storage of Request Smuggling Inspector state.
 * Plain ASCII text only.
 */
public class SmugglingSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<SmugglingPayloadDTO> payloads = new ArrayList<>();
    }

    public static class SmugglingPayloadDTO {
        public String name;
        public String description;
        public Map<String, String> headers = new LinkedHashMap<>();
        public String body;
    }
}
