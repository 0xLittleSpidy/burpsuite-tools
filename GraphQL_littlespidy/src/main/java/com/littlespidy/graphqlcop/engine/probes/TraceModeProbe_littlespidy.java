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

public class TraceModeProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.TRACE_MODE;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String query = "{\"query\": \"query { __typename }\"}";
        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, query,
                "Trace Mode Probe", logConsumer);

        if (pair != null && pair.response() != null) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.contains("\"tracing\"") || body.contains("\"tracing\":") ||
                    (body.contains("\"extensions\"") && (body.contains("duration") || body.contains("execution")))) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.TRACE_MODE,
                        AuditSeverity_littlespidy.LOW,
                        "GraphQL Field Tracing / Execution Metrics Disclosed",
                        "The GraphQL server response returned an 'extensions.tracing' block containing internal performance timings and resolver duration metrics.",
                        "Disable tracing and debug extensions in production configuration (e.g. tracing: false in Apollo Server).",
                        "Leads to timing information disclosure and reveals internal execution performance characteristics useful for timing side-channel attacks.",
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
