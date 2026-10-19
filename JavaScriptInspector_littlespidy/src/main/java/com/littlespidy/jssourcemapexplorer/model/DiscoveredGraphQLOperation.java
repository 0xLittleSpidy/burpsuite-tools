// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import java.util.Collections;
import java.util.Map;

/**
 * Represents a GraphQL query, mutation, subscription, or fragment extracted from
 * a JavaScript asset or an unpacked Source Map source file.
 *
 * @author littlespidy
 */
public record DiscoveredGraphQLOperation(
    String sourceLocation,
    String sourceType,
    String operationName,
    String operationType,       // Query, Mutation, Subscription, Fragment
    String queryBody,           // Full formatted GraphQL query body
    Map<String, Object> variables, // Inferred or extracted variable mappings
    String variablesJson,       // JSON representation of variable values
    String associatedEndpoint,  // Correlated endpoint path or URL (e.g. /graphql)
    String detectionEngine,     // Native Java or Babel AST
    String detectionTechnique,  // Tagged Template, React Hook, HTTP Body, etc.
    String riskCategory,        // Critical Mutation, Sensitive Fields, Standard
    int line,
    int startOffset,
    int endOffset,
    String snippet
) {
    public DiscoveredGraphQLOperation {
        if (variables == null) {
            variables = Collections.emptyMap();
        }
        if (variablesJson == null || variablesJson.isBlank()) {
            variablesJson = "{}";
        }
        if (associatedEndpoint == null || associatedEndpoint.isBlank()) {
            associatedEndpoint = "/graphql";
        }
        if (riskCategory == null || riskCategory.isBlank()) {
            riskCategory = "Standard";
        }
        if (detectionEngine == null || detectionEngine.isBlank()) {
            detectionEngine = "Native Java";
        }
    }
}
