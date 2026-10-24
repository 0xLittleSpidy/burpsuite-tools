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

import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public class GraphiqlProbe_littlespidy implements AuditProbe_littlespidy {
    private static final String[] EXPLORER_PATHS = {
            "/graphiql", "/graphql/console", "/playground", "/altair", "/explorer"
    };

    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.GRAPHIQL;
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();
        try {
            URI uri = new URI(targetUrl);
            String baseUrl = uri.getScheme() + "://" + uri.getAuthority();

            for (String path : EXPLORER_PATHS) {
                String testUrl = baseUrl + path;
                HttpRequest req = HttpHelper_littlespidy.createBaseRequest(testUrl, customHeaders)
                        .withMethod("GET")
                        .withHeader("Accept", "text/html,application/xhtml+xml");

                HttpRequestResponse pair = HttpHelper_littlespidy.sendCustom(api, req, "Explorer Probe: " + path, logConsumer);
                if (pair != null && pair.response() != null && pair.response().statusCode() == 200) {
                    String body = HttpHelper_littlespidy.getResponseBody(pair);
                    if (body.contains("GraphiQL") || body.contains("GraphQL Playground") || body.contains("Altair GraphQL")) {
                        String reqB64 = Base64.getEncoder().encodeToString(pair.request().toByteArray().getBytes());
                        String respB64 = Base64.getEncoder().encodeToString(pair.response().toByteArray().getBytes());

                        AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                                UUID.randomUUID().toString(),
                                AuditProbeType_littlespidy.GRAPHIQL,
                                AuditSeverity_littlespidy.LOW,
                                "GraphQL Interactive Explorer Exposed (" + path + ")",
                                "An interactive GraphQL web client (GraphiQL or Playground) was discovered accessible at: " + testUrl,
                                "Disable interactive web playgrounds in production environments.",
                                "Aids attackers in discovering schema operations, testing queries, and observing API behaviors directly in the browser.",
                                testUrl,
                                reqB64,
                                respB64
                        );
                        findings.add(finding);
                        break;
                    }
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
