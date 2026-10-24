// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.inql;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
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

public class EngineFingerprinter_littlespidy implements AuditProbe_littlespidy {
    private static final Gson GSON = new Gson();

    @Override
    public AuditProbeType_littlespidy getType() {
        return AuditProbeType_littlespidy.ENGINE_FINGERPRINT;
    }

    public static class FingerprintResult {
        public final String engineName;
        public final String technologies;
        public final String threatMatrixNotes;

        public FingerprintResult(String engineName, String technologies, String threatMatrixNotes) {
            this.engineName = engineName;
            this.technologies = technologies;
            this.threatMatrixNotes = threatMatrixNotes;
        }
    }

    @Override
    public List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                                  Consumer<HttpLogEntry_littlespidy> logConsumer) {
        List<AuditFinding_littlespidy> findings = new ArrayList<>();

        FingerprintResult result = detectEngine(api, targetUrl, customHeaders, logConsumer);
        if (result != null) {
            AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                    UUID.randomUUID().toString(),
                    AuditProbeType_littlespidy.ENGINE_FINGERPRINT,
                    AuditSeverity_littlespidy.INFO,
                    "GraphQL Engine Fingerprinted: " + result.engineName,
                    "Detected GraphQL engine: " + result.engineName + "\n" +
                            "Underlying Technologies: " + result.technologies + "\n\n" +
                            "Threat Matrix & Known Characteristics:\n" + result.threatMatrixNotes,
                    "Harden server configuration according to " + result.engineName + " security best practices. Disable unused features and mask debug errors.",
                    "Allows attackers to tailor exploit payloads specifically for " + result.engineName + " vulnerabilities and default behaviors.",
                    targetUrl,
                    "",
                    ""
            );
            findings.add(finding);
        }
        return findings;
    }

    public FingerprintResult detectEngine(MontoyaApi api, String targetUrl, String customHeaders,
                                         Consumer<HttpLogEntry_littlespidy> logConsumer) {
        // Probe 1: Apollo Server skip directive error
        String apolloSkipQuery = "{\"query\": \"query @skip { __typename }\"}";
        HttpRequestResponse apolloSkipResp = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders,
                apolloSkipQuery, "Fingerprint Probe: Apollo Directive", logConsumer);
        String apolloBody = HttpHelper_littlespidy.getResponseBody(apolloSkipResp);

        if (apolloBody.contains("Directive \\\"@skip\\\" argument \\\"if\\\" of type \\\"Boolean!\\\" is required") ||
                apolloBody.contains("Directive \"@skip\" argument \"if\" of type \"Boolean!\" is required")) {
            return new FingerprintResult("Apollo Server", "JavaScript / Node.js / TypeScript",
                    "Default introspection: On in dev, off in prod. Default tracing extensions available. Batch queries enabled by default unless explicitly disabled.");
        }

        // Probe 2: Hasura @cached directive & root typename
        String hasuraQuery = "{\"query\": \"query @cached { __typename }\"}";
        HttpRequestResponse hasuraResp = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders,
                hasuraQuery, "Fingerprint Probe: Hasura Directive", logConsumer);
        String hasuraBody = HttpHelper_littlespidy.getResponseBody(hasuraResp);
        if (hasuraBody.contains("query_root") || hasuraBody.contains("hasura")) {
            return new FingerprintResult("Hasura GraphQL Engine", "Haskell / PostgreSQL",
                    "Role-based authorization checks, automatic SQL compilation. Check for unauthenticated schema access on /v1/graphql.");
        }

        // Probe 3: AWS AppSync
        if (apolloBody.contains("MisplacedDirective") || apolloBody.contains("ValidationException")) {
            return new FingerprintResult("AWS AppSync", "AWS Managed / Java",
                    "Direct DynamoDB/Lambda integration. Inspect IAM / API Key requirements in headers.");
        }

        // Probe 4: Graphene syntax error
        String syntaxErrorQuery = "{\"query\": \"invalid_syntax_root\"}";
        HttpRequestResponse syntaxResp = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders,
                syntaxErrorQuery, "Fingerprint Probe: Syntax Error Format", logConsumer);
        String syntaxBody = HttpHelper_littlespidy.getResponseBody(syntaxResp);
        if (syntaxBody.contains("Syntax Error GraphQL (1:1)")) {
            return new FingerprintResult("Graphene", "Python / Django / Flask",
                    "Python AST parsing. Check for unhandled exceptions in resolver resolvers and debug flag disclosures.");
        }

        // Probe 5: GraphQL Yoga subscription error
        String yogaQuery = "{\"query\": \"subscription { __typename }\"}";
        HttpRequestResponse yogaResp = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders,
                yogaQuery, "Fingerprint Probe: GraphQL Yoga Subscription", logConsumer);
        String yogaBody = HttpHelper_littlespidy.getResponseBody(yogaResp);
        if (yogaBody.contains("asyncExecutionResult[Symbol.asyncIterator] is not a function") ||
                yogaBody.contains("Unexpected error.")) {
            return new FingerprintResult("GraphQL Yoga", "JavaScript / TypeScript / Envelop",
                    "Envelop plugin architecture. Verify if GraphiQL is accessible at root URL or /graphql.");
        }

        // Probe 6: WPGraphQL
        String wpQuery = "{\"query\": \"query { posts { nodes { id } } }\"}";
        HttpRequestResponse wpResp = HttpHelper_littlespidy.sendJsonPost(api, targetUrl, customHeaders,
                wpQuery, "Fingerprint Probe: WPGraphQL Nodes", logConsumer);
        String wpBody = HttpHelper_littlespidy.getResponseBody(wpResp);
        if (wpBody.contains("wpgraphql") || wpBody.contains("wp-graphql")) {
            return new FingerprintResult("WPGraphQL", "PHP / WordPress",
                    "Exposes WordPress database models. Check for user enumeration via 'users' node and private posts disclosure.");
        }

        // Probe 7: GraphQL-Java / Spring Boot
        if (syntaxBody.contains("InvalidSyntaxException") || syntaxBody.contains("Validation error of type")) {
            return new FingerprintResult("GraphQL-Java", "Java / Spring Boot",
                    "Check max query depth and instrumentation options. Inspect error extensions for class name leakage.");
        }

        // Probe 8: Ruby GraphQL
        if (syntaxBody.contains("Parse error on \"invalid_syntax_root\"")) {
            return new FingerprintResult("Ruby GraphQL", "Ruby on Rails",
                    "Check for multiplex queries support (batching) and max complexity filters.");
        }

        // Probe 9: Mercurius
        if (syntaxBody.contains("GraphQLError: Syntax Error") && syntaxBody.contains("mercurius")) {
            return new FingerprintResult("Mercurius", "Fastify / Node.js",
                    "Fastify plugin. Check query depth and JIT compilation settings.");
        }

        // Probe 10: Hot Chocolate (.NET)
        if (syntaxBody.contains("HC0014") || syntaxBody.contains("HotChocolate")) {
            return new FingerprintResult("Hot Chocolate", "C# / .NET Core",
                    "Microsoft .NET GraphQL server. Inspect Banana Cake Pop IDE availability.");
        }

        return new FingerprintResult("Generic GraphQL Server", "Unknown Stack",
                "Standard GraphQL specification compliance. Review probe findings for specific misconfigurations.");
    }
}
