// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.engine.probes;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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

public class PostCsrfProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.POST_CSRF;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String formBody = "query=query%7B__typename%7D";

        HttpRequest req = HttpHelper_littlespidy.createBaseRequest(targetUrl, customHeaders)
                .withMethod("POST")
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withHeader("Accept", "application/json")
                .withBody(formBody);

        HttpRequestResponse pair = HttpHelper_littlespidy.sendCustom(api, req, "POST URL-Encoded CSRF Check", logConsumer);
        if (pair != null && pair.response() != null && pair.response().statusCode() == 200) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.contains("__typename") || body.contains("data")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.POST_CSRF,
                        AuditSeverity_littlespidy.HIGH,
                        "GraphQL Accepts application/x-www-form-urlencoded (CSRF Vulnerable)",
                        "The GraphQL server successfully processed a query sent with application/x-www-form-urlencoded Content-Type. " +
                                "Standard HTML forms can forge cross-origin POST requests with this content type without triggering CORS preflights.",
                        "Strictly require application/json Content-Type and reject URL-encoded submissions. Ensure anti-CSRF tokens or custom headers are required.",
                        "Cross-Site Request Forgery (CSRF) can allow attacker websites to trigger unauthorized queries or mutations on behalf of logged-in users.",
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
