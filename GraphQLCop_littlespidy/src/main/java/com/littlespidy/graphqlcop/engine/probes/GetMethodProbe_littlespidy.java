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

public class GetMethodProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.GET_METHOD;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String delimiter = targetUrl.contains("?") ? "&" : "?";
        String testUrl = targetUrl + delimiter + "query=query%7B__typename%7D";

        HttpRequest req = HttpHelper_littlespidy.createBaseRequest(testUrl, customHeaders)
                .withMethod("GET")
                .withHeader("Accept", "application/json");

        HttpRequestResponse pair = HttpHelper_littlespidy.sendCustom(api, req, "GET Method Support", logConsumer);
        if (pair != null && pair.response() != null && pair.response().statusCode() == 200) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.contains("__typename") || body.contains("data")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.GET_METHOD,
                        AuditSeverity_littlespidy.MEDIUM,
                        "GraphQL Queries Supported via GET Method",
                        "The GraphQL server accepted and executed operations sent via HTTP GET requests. " +
                                "GET requests can be cached by intermediaries, stored in browser history, and logged in server access logs.",
                        "Enforce POST requests exclusively for GraphQL queries, or strictly disallow sensitive parameters over GET.",
                        "Sensitive queries may leak via server logs, proxy access logs, and browser history. May also facilitate Cross-Site Request Forgery.",
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
