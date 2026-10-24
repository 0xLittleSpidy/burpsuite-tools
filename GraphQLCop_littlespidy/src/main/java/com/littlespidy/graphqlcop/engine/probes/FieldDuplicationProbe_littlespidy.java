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

public class FieldDuplicationProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.FIELD_DUPLICATION;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();

        StringBuilder duplicatedFields = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            duplicatedFields.append("__typename ");
        }
        String query = "{\"query\": \"query { " + duplicatedFields.toString() + " }\"}";

        HttpRequestResponse pair = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders, query,
                "Field Duplication Probe (400 duplicates)", logConsumer);

        if (pair != null && pair.response() != null && pair.response().statusCode() == 200) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.contains("__typename") || body.contains("data")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.FIELD_DUPLICATION,
                        AuditSeverity_littlespidy.MEDIUM,
                        "Field Duplication Allowed (Denial of Service)",
                        "The server evaluated hundreds of duplicate fields in a single query without deduplication or complexity limiting.",
                        "Enforce query cost analysis rules and reject queries containing excessive identical or redundant field selections.",
                        "Amplified server processing load, CPU consumption, and potential resource starvation.",
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
