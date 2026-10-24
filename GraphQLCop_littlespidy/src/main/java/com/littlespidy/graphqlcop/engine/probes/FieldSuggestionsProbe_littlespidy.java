// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.engine.probes;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.littlespidy.graphqlcop.engine.AuditProbe_littlespidy;
import com.littlespidy.graphqlcop.engine.HttpHelper_littlespidy;
import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.AuditSeverity_littlespidy;
import com.littlespidy.graphqlcop.model.HttpLogEntry_littlespidy;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public class FieldSuggestionsProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.FIELD_SUGGESTIONS;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String query = "{\"query\": \"query { __schemaa }\"}";
        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, query,
                "Field Suggestions Probe", logConsumer);

        if (pair != null && pair.response() != null) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.toLowerCase().contains("did you mean")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.FIELD_SUGGESTIONS,
                        AuditSeverity_littlespidy.LOW,
                        "GraphQL Field Suggestions Enabled (Blind Schema Leakage)",
                        "The GraphQL server suggests correct field names when an incorrect field name is submitted (e.g. 'Did you mean __schema?').",
                        "Disable field suggestions in production (or mask errors) to prevent schema recovery tools like Clairvoyance from reconstructing the schema.",
                        "Even if Introspection is disabled, attackers can brute-force and reconstruct the entire schema using suggestion oracles.",
                        targetUrl,
                        reqB64,
                        respB64
                );
                findings.add(finding);
            }
        }
        return findings;
    }
}
