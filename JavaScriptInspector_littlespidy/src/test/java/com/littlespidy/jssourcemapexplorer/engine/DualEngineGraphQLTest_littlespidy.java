// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredGraphQLOperation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Automated tests for DualEngineGraphQLCoordinator_littlespidy.
 *
 * @author littlespidy
 */
class DualEngineGraphQLTest_littlespidy {

    @Test
    @DisplayName("Verify coordinator extracts operations and handles non-graphql files gracefully")
    void testCoordinatorExecution() {
        String nonGql = "function add(a, b) { return a + b; }";
        List<DiscoveredGraphQLOperation> empty = DualEngineGraphQLCoordinator_littlespidy.extractOperations(
            "https://example.com/math.js", "JS File", nonGql
        );
        assertTrue(empty.isEmpty(), "Non-graphql files should produce empty list");

        String gqlJs = """
            const QUERY = `query GetCatalog {
              products {
                id
                name
                price
              }
            }`;
            """;
        List<DiscoveredGraphQLOperation> ops = DualEngineGraphQLCoordinator_littlespidy.extractOperations(
            "https://example.com/shop.js", "JS File", gqlJs
        );
        assertFalse(ops.isEmpty(), "Should extract operations via dual coordinator");
        assertEquals("GetCatalog", ops.get(0).operationName());
        assertEquals("Query", ops.get(0).operationType());
    }
}
