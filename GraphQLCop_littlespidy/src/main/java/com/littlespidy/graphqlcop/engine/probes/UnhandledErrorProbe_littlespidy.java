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

public class UnhandledErrorProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.UNHANDLED_ERROR;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String malformedQuery = "{\"query\": \"query { 1 }\"}";

        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, malformedQuery,
                "Unhandled Error Probe", logConsumer);

        if (pair != null && pair.response() != null) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            boolean leaksStack = body.contains("Traceback (most recent call last)") ||
                    body.contains("Exception in thread") ||
                    body.contains("at com.") ||
                    body.contains("at org.") ||
                    body.contains("at java.") ||
                    body.contains("node_modules/") ||
                    body.contains("/vendor/") ||
                    body.contains(".php on line") ||
                    body.contains("stacktrace");

            if (leaksStack) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.UNHANDLED_ERROR,
                        AuditSeverity_littlespidy.MEDIUM,
                        "Unhandled Error / Internal Stack Trace Disclosed",
                        "The server returned detailed internal application stack traces, framework file paths, or exception details upon receiving malformed input.",
                        "Configure generic error masking in production to strip stack traces, file paths, and internal exceptions.",
                        "Reveals internal server technology stacks, third-party library versions, and file paths useful for targeted exploitation.",
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
