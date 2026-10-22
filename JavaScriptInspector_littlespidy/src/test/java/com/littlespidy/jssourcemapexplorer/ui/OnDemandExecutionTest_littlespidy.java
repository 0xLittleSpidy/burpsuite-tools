// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying on-demand execution decoupling between Recon and GraphQL operations,
 * preserving findings independently without cross-over wiping.
 *
 * @author littlespidy
 */
class OnDemandExecutionTest_littlespidy {

    @Test
    @DisplayName("Verify Recon findings do not overwrite or clear GraphQL operations")
    void testReconFindingsDoNotClearGraphQLOperations() {
        JsFileEntry entry = new JsFileEntry(
            1,
            "https://target.com/app.js",
            "target.com",
            "/app.js",
            200,
            2048,
            true,
            "1st Party",
            PassiveMapStatus.NOT_FOUND,
            null,
            null,
            null,
            ZonedDateTime.now()
        );

        // Pre-populate GraphQL findings
        DiscoveredGraphQLOperation op = new DiscoveredGraphQLOperation(
            "https://target.com/app.js",
            "JS File",
            "GetUserQuery",
            "Query",
            "query GetUser { user { id name } }",
            Collections.emptyMap(),
            "{}",
            "https://target.com/graphql",
            "Babel AST",
            "Template",
            "Standard",
            10,
            120,
            150,
            "query GetUser..."
        );
        entry.setJsGraphQLOperations(List.of(op));
        assertEquals(1, entry.getJsGraphQLOperations().size(), "GraphQL operations should be set");

        // Run Recon findings setter
        DiscoveredSecret secret = new DiscoveredSecret(
            "app.js",
            "JS File",
            "API Key",
            "AIzaSyD-dummy-key-1234567890",
            "High",
            4.1,
            "High",
            "Regex",
            5,
            50,
            75,
            "const key = 'AIzaSyD-dummy-key-1234567890';"
        );
        DiscoveredEndpoint endpoint = new DiscoveredEndpoint(
            "app.js",
            "JS File",
            "/api/v1/auth",
            "POST",
            15,
            150,
            162,
            "fetch('/api/v1/auth')",
            "Regex"
        );

        entry.setJsReconFindings(
            List.of(secret),
            List.of(endpoint),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList()
        );

        // Verify both sets of findings are preserved
        assertEquals(1, entry.getJsSecrets().size(), "Secrets should be preserved");
        assertEquals(1, entry.getJsEndpoints().size(), "Endpoints should be preserved");
        assertEquals(1, entry.getJsGraphQLOperations().size(), "GraphQL operations must NOT be wiped by Recon setter");
        assertEquals("GetUserQuery", entry.getJsGraphQLOperations().get(0).operationName());
    }

    @Test
    @DisplayName("Verify GraphQL operations do not overwrite or clear Recon findings")
    void testGraphQLOperationsDoNotClearReconFindings() {
        JsFileEntry entry = new JsFileEntry(
            2,
            "https://target.com/main.js",
            "target.com",
            "/main.js",
            200,
            4096,
            true,
            "1st Party",
            PassiveMapStatus.NOT_FOUND,
            null,
            null,
            null,
            ZonedDateTime.now()
        );

        // Pre-populate Recon findings
        DiscoveredSecret secret = new DiscoveredSecret(
            "main.js",
            "JS File",
            "Token",
            "secret-token-xyz-12345",
            "High",
            3.9,
            "High",
            "Regex",
            10,
            100,
            123,
            "const token = 'secret-token-xyz-12345';"
        );
        entry.setJsReconFindings(
            List.of(secret),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyList()
        );
        assertEquals(1, entry.getJsSecrets().size(), "Secrets should be set");

        // Run GraphQL setter
        DiscoveredGraphQLOperation op = new DiscoveredGraphQLOperation(
            "https://target.com/main.js",
            "JS File",
            "UpdateUserMutation",
            "Mutation",
            "mutation UpdateUser($id: ID!) { updateUser(id: $id) { success } }",
            Collections.emptyMap(),
            "{\"id\":\"1\"}",
            "https://target.com/graphql",
            "Native Java",
            "Hook",
            "Critical Mutation",
            25,
            200,
            260,
            "mutation UpdateUser..."
        );
        entry.setJsGraphQLOperations(List.of(op));

        // Verify Recon findings remain intact
        assertEquals(1, entry.getJsSecrets().size(), "Recon findings must NOT be wiped by GraphQL setter");
        assertEquals(1, entry.getJsGraphQLOperations().size(), "GraphQL operations should be set");
    }
}
