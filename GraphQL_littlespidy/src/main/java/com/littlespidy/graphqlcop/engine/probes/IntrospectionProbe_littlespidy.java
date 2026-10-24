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

public class IntrospectionProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.INTROSPECTION;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String query = "{\"query\": \"query { __schema { types { name } } }\"}";
        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, query,
                "Introspection Query", logConsumer);

        if (pair != null && pair.response() != null) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.contains("__schema") && body.contains("types")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.INTROSPECTION,
                        AuditSeverity_littlespidy.HIGH,
                        "GraphQL Introspection Query Enabled",
                        "The GraphQL endpoint allows full schema introspection via the __schema query. " +
                                "This permits unauthenticated attackers to discover all queries, mutations, subscriptions, types, and internal fields.",
                        "Disable introspection in production environments (e.g. introspection: false in Apollo Server, or schema filters).",
                        "Full exposure of API schema, business logic, unpublished models, and hidden administrative mutations.",
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
