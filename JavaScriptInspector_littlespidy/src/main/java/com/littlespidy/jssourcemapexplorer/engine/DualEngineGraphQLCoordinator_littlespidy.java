// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.DiscoveredGraphQLOperation;

import java.util.*;

/**
 * Coordinates dual-engine GraphQL detection across the native Java engine
 * and the external Node.js Babel AST engine.
 *
 * Ensures high-speed real-time detection in all environments while seamlessly
 * leveraging deep 3-pass Babel AST lexical analysis whenever Node.js is present.
 *
 * @author littlespidy
 */
public class DualEngineGraphQLCoordinator_littlespidy {

    public static List<DiscoveredGraphQLOperation> extractOperations(
        String sourceLocation,
        String sourceType,
        String code
    ) {
        if (code == null || code.isBlank() || code.length() < 12) {
            return Collections.emptyList();
        }

        // 1. Run Native Java Engine (fast, zero external dependencies)
        List<DiscoveredGraphQLOperation> nativeOps = GraphQLMiner_littlespidy.mine(sourceLocation, sourceType, code);

        // 2. Check if code contains GraphQL indicators and Node.js Babel AST bridge is available
        boolean hasGqlIndicators = containsGqlKeywords(code);
        List<DiscoveredGraphQLOperation> astOps = Collections.emptyList();

        if (hasGqlIndicators && SchemaFinderAstBridge_littlespidy.isNodeAvailable()) {
            try {
                astOps = SchemaFinderAstBridge_littlespidy.extractWithBabelAst(sourceLocation, sourceType, code);
            } catch (Exception ignored) {}
        }

        if (astOps.isEmpty()) {
            return nativeOps;
        }
        if (nativeOps.isEmpty()) {
            return astOps;
        }

        // 3. Deduplicate and merge results from both engines
        Map<String, DiscoveredGraphQLOperation> merged = new LinkedHashMap<>();

        // Register Native Java operations first
        for (DiscoveredGraphQLOperation op : nativeOps) {
            String key = normalizeKey(op.operationType(), op.operationName(), op.queryBody());
            merged.put(key, op);
        }

        // Merge or append AST operations
        for (DiscoveredGraphQLOperation astOp : astOps) {
            String key = normalizeKey(astOp.operationType(), astOp.operationName(), astOp.queryBody());
            if (merged.containsKey(key)) {
                DiscoveredGraphQLOperation existing = merged.get(key);
                // Enhance existing operation with dual engine status and combined techniques
                String combinedEngine = "Dual Engine (Native + AST)";
                String combinedTechnique = existing.detectionTechnique() + " / AST (" + astOp.detectionTechnique() + ")";
                merged.put(key, new DiscoveredGraphQLOperation(
                    existing.sourceLocation(),
                    existing.sourceType(),
                    existing.operationName(),
                    existing.operationType(),
                    existing.queryBody(),
                    existing.variables().isEmpty() ? astOp.variables() : existing.variables(),
                    existing.variablesJson().equals("{}") ? astOp.variablesJson() : existing.variablesJson(),
                    existing.associatedEndpoint(),
                    combinedEngine,
                    combinedTechnique,
                    existing.riskCategory(),
                    existing.line(),
                    existing.startOffset(),
                    existing.endOffset(),
                    existing.snippet()
                ));
            } else {
                merged.put(key, astOp);
            }
        }

        return new ArrayList<>(merged.values());
    }

    private static boolean containsGqlKeywords(String text) {
        return text.contains("query") || text.contains("mutation")
            || text.contains("subscription") || text.contains("fragment");
    }

    private static String normalizeKey(String type, String name, String query) {
        String compactQuery = query.replaceAll("\\s+", " ").strip();
        return (type + ":" + name + ":" + compactQuery).toLowerCase(Locale.ROOT);
    }
}
