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

public class AliasOverloadProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.ALIAS_OVERLOAD;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();

        StringBuilder aliases = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            aliases.append("a").append(i).append(": __typename ");
        }
        String query = "{\"query\": \"query { " + aliases.toString() + " }\"}";

        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, query,
                "Alias Overloading Probe (100 aliases)", logConsumer);

        if (pair != null && pair.response() != null && pair.response().statusCode() == 200) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.contains("a0") && body.contains("a99")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.ALIAS_OVERLOAD,
                        AuditSeverity_littlespidy.MEDIUM,
                        "GraphQL Alias Overloading Allowed (Rate Limit Bypass / DoS)",
                        "The server evaluated 100 field aliases in a single query payload without alias count limitations.",
                        "Enforce alias limits (e.g. maximum 10-15 aliases per query) and compute field execution costs.",
                        "Enables attackers to bypass rate limiting on sensitive operations (e.g. password resets, OTP verification) and cause DoS.",
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
