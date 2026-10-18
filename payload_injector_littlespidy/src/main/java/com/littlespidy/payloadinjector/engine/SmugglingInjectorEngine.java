// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.payloadinjector.model.SmugglingPayloadEntry;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Engine responsible for applying HTTP request smuggling payloads to requests.
 * Replaces request body with the chunked payload and overrides headers
 * (e.g. Content-Length and Transfer-Encoding) in correct sequence to preserve
 * desync discrepancy conditions.
 *
 * @author littlespidy
 */
public class SmugglingInjectorEngine {

    /**
     * Applies the given smuggling payload to the request:
     * 1. Replaces body with decoded body bytes (\r\n decoded to CRLF).
     * 2. Sets/updates headers AFTER withBody() to avoid withBody() recalculating Content-Length.
     */
    public static HttpRequest applyPayload(HttpRequest request, SmugglingPayloadEntry entry) {
        if (request == null || entry == null) {
            return request;
        }

        // Step 1: replace body (withBody auto-calculates real body size)
        HttpRequest mutated = request.withBody(entry.getDecodedBody());

        // Step 2: explicitly set deliberate discrepancy headers declared in the entry
        for (var header : entry.getHeaders().entrySet()) {
            mutated = mutated.hasHeader(header.getKey())
                    ? mutated.withUpdatedHeader(header.getKey(), header.getValue())
                    : mutated.withAddedHeader(header.getKey(), header.getValue());
        }

        return mutated;
    }
}
