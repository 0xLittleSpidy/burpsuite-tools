// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.model;

import java.util.Collections;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable value object representing a single HTTP request-smuggling payload
 * loaded from {@code smuggling-payloads.json}.
 *
 * <p>The {@code body} field stores the raw body string as written in the JSON
 * file (e.g. {@code "0\r\n\r\nHELLO"} with literal backslash-r-backslash-n
 * characters). Call {@link #getDecodedBody()} to obtain the value with those
 * escape sequences converted to actual CR+LF bytes, ready for injection.
 *
 * @author littlespidy
 */
public class PayloadEntry {

    private final String name;
    private final String description;
    private final Map<String, String> headers;
    private final String body;

    public PayloadEntry(String name,
                        String description,
                        Map<String, String> headers,
                        String body) {
        this.name        = name        != null ? name        : "";
        this.description = description != null ? description : "";
        this.headers     = headers     != null ? Collections.unmodifiableMap(headers)
                                               : Collections.emptyMap();
        this.body        = body        != null ? body        : "";
    }

    /** Display name shown in the context menu and the Payloads tab. */
    public String getName() { return name; }

    /** Optional tooltip / notes shown in the detail pane of the Payloads tab. */
    public String getDescription() { return description; }

    /**
     * Headers to set or update on the request (e.g. Transfer-Encoding, Content-Length).
     * Keys are header names; values are header values.
     */
    public Map<String, String> getHeaders() { return headers; }

    /**
     * Raw body string as stored in the JSON file.
     * Literal {@code \r\n} sequences are NOT yet decoded.
     * Shown as-is in the Payloads tab "Payload Value" column.
     */
    public String getBody() { return body; }

    /**
     * Returns the body ready for injection: literal {@code \r\n} text sequences
     * are converted to actual CR+LF (0x0D 0x0A) bytes.
     */
    public String getDecodedBody() {
        return body.replace("\\r\\n", "\r\n");
    }
}
