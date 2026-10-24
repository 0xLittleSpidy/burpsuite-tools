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

public class DirectiveOverloadProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.DIRECTIVE_OVERLOAD;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();

        StringBuilder directives = new StringBuilder();
        for (int i = 0; i < 1200; i++) {
            directives.append("@aa");
        }
        String query = "{\"query\": \"query { __typename " + directives.toString() + " }\"}";

        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, query,
                "Directive Overload Probe (1200 directives)", logConsumer);

        if (pair != null && pair.response() != null) {
            int status = pair.response().statusCode();
            String body = HttpHelper_littlespidy.getResponseBody(pair);

            if (status == 200 || status == 500 || body.contains("OutOfMemory") || body.contains("Max directive") || body.contains("stack overflow")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.DIRECTIVE_OVERLOAD,
                        AuditSeverity_littlespidy.HIGH,
                        "GraphQL Directive Overloading (Denial of Service)",
                        "The server accepted or crashed upon receiving a query containing over 1,200 repeated directives without validation or limiting.",
                        "Enforce AST directive count limits, query parsing timeouts, and validation rules to reject excessive directives before execution.",
                        "Denial of Service (DoS) via CPU exhaustion and memory depletion during query parsing and AST construction.",
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
