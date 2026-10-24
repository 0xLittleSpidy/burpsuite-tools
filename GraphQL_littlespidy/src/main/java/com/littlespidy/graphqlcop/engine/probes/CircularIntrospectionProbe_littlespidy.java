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

public class CircularIntrospectionProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.CIRCULAR_INTROSPECTION;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String query = "{\"query\": \"query { __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }\"}";

        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, query,
                "Circular Introspection Query", logConsumer);

        if (pair != null && pair.response() != null) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (pair.response().statusCode() == 200 && (body.contains("__schema") || body.contains("fields"))) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.CIRCULAR_INTROSPECTION,
                        AuditSeverity_littlespidy.HIGH,
                        "Circular Introspection Query Execution (Query Depth Flaw)",
                        "The server evaluated deeply nested, cyclic introspection queries without query depth limitations.",
                        "Implement strict query depth and query complexity limiting (e.g. max depth 7-10). Disable introspection in production.",
                        "Denial of Service (DoS) through recursive introspection query amplification, causing heavy CPU and memory consumption.",
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
