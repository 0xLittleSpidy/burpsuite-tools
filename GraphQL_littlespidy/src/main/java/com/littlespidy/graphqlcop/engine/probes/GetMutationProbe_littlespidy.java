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

public class GetMutationProbe_littlespidy implements AuditProbe_littlespidy {
    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.GET_MUTATION;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        String delimiter = targetUrl.contains("?") ? "&" : "?";
        String testUrl = targetUrl + delimiter + "query=mutation%7B__typename%7D";

        HttpRequest req = HttpHelper_littlespidy.createBaseRequest(testUrl, customHeaders)
                .withMethod("GET")
                .withHeader("Accept", "application/json");

        HttpRequestResponse pair = HttpHelper_littlespidy.sendCustom(api, req, "GET Mutation Probe", logConsumer);
        if (pair != null && pair.response() != null && pair.response().statusCode() == 200) {
            String body = HttpHelper_littlespidy.getResponseBody(pair);
            if (body.contains("__typename") || body.contains("data")) {
                String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                        UUID.randomUUID().toString(),
                        AuditProbeType_littlespidy.GET_MUTATION,
                        AuditSeverity_littlespidy.HIGH,
                        "State-Modifying Mutations Permitted via HTTP GET",
                        "The server accepted and processed a mutation operation submitted via an HTTP GET query parameter.",
                        "Strictly restrict mutation operations to HTTP POST requests with appropriate CSRF defenses.",
                        "Enables Cross-Site Request Forgery (CSRF) via simple image tags, links, or prefetching, allowing attackers to execute state-changing mutations without user awareness.",
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
