// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredGraphQLOperation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive automated tests for native Java GraphQL extraction engine.
 *
 * @author littlespidy
 */
class GraphQLMinerTest_littlespidy {

    @Test
    @DisplayName("Extract tagged template GraphQL query")
    void testTaggedTemplateExtraction() {
        String js = """
            import { gql } from '@apollo/client';
            const GET_USER_PROFILE = gql`
              query GetUserProfile($userId: ID!, $includeHistory: Boolean = false) {
                user(id: $userId) {
                  id
                  username
                  email
                  roles
                  profile {
                    avatarUrl
                    bio
                  }
                }
              }
            `;
            """;

        List<DiscoveredGraphQLOperation> ops = GraphQLMiner_littlespidy.mine("https://example.com/app.js", "JS File", js);
        assertFalse(ops.isEmpty(), "Should discover tagged template query");

        DiscoveredGraphQLOperation op = ops.stream()
            .filter(o -> "GetUserProfile".equals(o.operationName()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("GetUserProfile query not found"));

        assertEquals("Query", op.operationType());
        assertTrue(op.queryBody().contains("user(id: $userId)"));
        assertTrue(op.queryBody().contains("profile {"));
        assertTrue(op.variables().containsKey("userId"));
        assertTrue(op.variables().containsKey("includeHistory"));
        assertEquals("Sensitive Fields", op.riskCategory()); // contains 'email'
    }

    @Test
    @DisplayName("Extract critical mutation with high risk rating")
    void testCriticalMutationExtraction() {
        String js = """
            const DELETE_ACCOUNT_MUTATION = gql`
              mutation DeleteUserAccount($userId: ID!, $passwordConfirmation: String!) {
                deleteAccount(id: $userId, password: $passwordConfirmation) {
                  success
                  message
                }
              }
            `;
            """;

        List<DiscoveredGraphQLOperation> ops = GraphQLMiner_littlespidy.mine("https://example.com/account.js", "JS File", js);
        assertFalse(ops.isEmpty());

        DiscoveredGraphQLOperation op = ops.get(0);
        assertEquals("Mutation", op.operationType());
        assertEquals("DeleteUserAccount", op.operationName());
        assertEquals("Critical Mutation", op.riskCategory());
        assertTrue(op.variablesJson().contains("userId"));
        assertTrue(op.variablesJson().contains("passwordConfirmation"));
    }

    @Test
    @DisplayName("Extract React Apollo hooks useQuery and useMutation")
    void testReactApolloHooks() {
        String js = """
            function UserWidget() {
              const { data, loading } = useQuery(gql`
                query FetchDashboardStats($period: String) {
                  stats(period: $period) {
                    views
                    conversions
                  }
                }
              `);
              return <div>{loading ? 'loading' : data}</div>;
            }
            """;

        List<DiscoveredGraphQLOperation> ops = GraphQLMiner_littlespidy.mine("https://example.com/dashboard.js", "JS File", js);
        assertFalse(ops.isEmpty());
        assertTrue(ops.stream().anyMatch(o -> "FetchDashboardStats".equals(o.operationName())));
    }

    @Test
    @DisplayName("Extract HTTP client body query (fetch / axios)")
    void testHttpClientBodyExtraction() {
        String js = """
            async function loadData() {
              const res = await fetch("/api/v2/graphql", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  query: "query GetInternalConfig { system { version debugMode } }"
                })
              });
              return res.json();
            }
            """;

        List<DiscoveredGraphQLOperation> ops = GraphQLMiner_littlespidy.mine("https://example.com/client.js", "JS File", js);
        assertFalse(ops.isEmpty());
        assertTrue(ops.stream().anyMatch(o -> "GetInternalConfig".equals(o.operationName())));
    }

    @Test
    @DisplayName("Extract resolved string concatenations")
    void testStringConcatenationResolution() {
        String js = """
            const q = 'query ' + 'LazyLoadedReport ' + '{ ' +
                      '  report { id name timestamp } ' +
                      '}';
            """;

        List<DiscoveredGraphQLOperation> ops = GraphQLMiner_littlespidy.mine("https://example.com/report.js", "JS File", js);
        assertFalse(ops.isEmpty(), "Should extract concatenated query");
        assertTrue(ops.stream().anyMatch(o -> "LazyLoadedReport".equals(o.operationName())));
    }

    @Test
    @DisplayName("Extract commented out GraphQL operation")
    void testCommentedOutQuery() {
        String js = """
            // TODO: Deprecate old mutation
            // mutation RevokeToken($tokenId: String!) {
            //   revoke(token: $tokenId) { status }
            // }
            const active = true;
            """;

        List<DiscoveredGraphQLOperation> ops = GraphQLMiner_littlespidy.mine("https://example.com/auth.js", "JS File", js);
        assertFalse(ops.isEmpty(), "Should extract commented-out query");
        assertTrue(ops.stream().anyMatch(o -> "RevokeToken".equals(o.operationName())));
    }

    @Test
    @DisplayName("Extract Base64 encoded GraphQL operation")
    void testBase64EncodedQuery() {
        String rawGql = "query GetHiddenSecrets { secrets { apiKey privateKey } }";
        String b64 = Base64.getEncoder().encodeToString(rawGql.getBytes(StandardCharsets.UTF_8));
        String js = "const encodedPayload = \"" + b64 + "\";";

        List<DiscoveredGraphQLOperation> ops = GraphQLMiner_littlespidy.mine("https://example.com/bundle.js", "JS File", js);
        assertFalse(ops.isEmpty(), "Should decode and extract Base64 GraphQL query");
        assertTrue(ops.stream().anyMatch(o -> "GetHiddenSecrets".equals(o.operationName())));
    }

    @Test
    @DisplayName("Verify variable signature parsing and default mock synthesis")
    void testVariableSignatureParsing() {
        String query = "query SearchUsers($query: String!, $limit: Int = 20, $offset: Int, $isActive: Boolean, $tags: [String]) { search { id } }";
        Map<String, Object> vars = GraphQLMiner_littlespidy.extractVariablesFromSignature(query);

        assertEquals(5, vars.size());
        assertEquals("", vars.get("query"));
        assertEquals(0, vars.get("limit"));
        assertEquals(0, vars.get("offset"));
        assertEquals(false, vars.get("isActive"));
        assertEquals(List.of(), vars.get("tags"));

        String json = GraphQLMiner_littlespidy.buildVariablesJson(vars);
        assertTrue(json.contains("\"query\": \"\""));
        assertTrue(json.contains("\"limit\": 0"));
        assertTrue(json.contains("\"isActive\": false"));
    }
}
