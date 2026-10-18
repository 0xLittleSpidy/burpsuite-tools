// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import java.util.Collections;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable value object representing a single HTTP request smuggling payload
 * loaded from {@code http_request_smuggling_payloads.json}.
 *
 * <p>The {@code body} field stores the raw body string as written in the JSON
 * file (e.g. {@code "0\r\n\r\nHELLO"}). Call {@link #getDecodedBody()} to
 * obtain the value with escape sequences converted to actual CR+LF bytes.
 *
 * @author littlespidy
 */
public class SmugglingPayloadEntry {

    private final String name;
    private final String description;
    private final Map<String, String> headers;
    private final String body;
    private final String sourceType;
    private final String sourceFile;

    public SmugglingPayloadEntry(String name,
                                 String description,
                                 Map<String, String> headers,
                                 String body) {
        this(name, description, headers, body, "Manual", "N/A");
    }

    public SmugglingPayloadEntry(String name,
                                 String description,
                                 Map<String, String> headers,
                                 String body,
                                 String sourceType,
                                 String sourceFile) {
        this.name        = name        != null ? name        : "";
        this.description = description != null ? description : "";
        this.headers     = headers     != null ? Collections.unmodifiableMap(headers)
                                               : Collections.emptyMap();
        this.body        = body        != null ? body        : "";
        this.sourceType  = (sourceType != null && !sourceType.isBlank()) ? sourceType : "Manual";
        this.sourceFile  = (sourceFile != null && !sourceFile.isBlank()) ? sourceFile : "N/A";
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public String getSourceType() {
        return sourceType;
    }

    public String getSourceFile() {
        return sourceFile;
    }

    /**
     * Converts literal {@code \r\n} text sequences to actual CR+LF (0x0D 0x0A) bytes.
     */
    public String getDecodedBody() {
        return body.replace("\\r\\n", "\r\n");
    }
}
