// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.model;

public enum AuditProbeType_littlespidy {
    INTROSPECTION("GraphQL Introspection", "Information Disclosure"),
    GRAPHIQL("GraphiQL / Playground Explorer", "Information Disclosure"),
    GET_METHOD("GET Method Support", "Method Handling"),
    POST_CSRF("POST-based CSRF Support", "CSRF Protection"),
    TRACE_MODE("Tracing / Debug Mode", "Information Disclosure"),
    FIELD_SUGGESTIONS("Field Suggestions", "Information Disclosure"),
    DIRECTIVE_OVERLOAD("Directive Overloading", "Denial of Service"),
    CIRCULAR_INTROSPECTION("Circular Introspection", "Denial of Service"),
    FIELD_DUPLICATION("Field Duplication", "Denial of Service"),
    ALIAS_OVERLOAD("Alias Overloading", "Denial of Service"),
    BATCH_QUERY("Batch Queries", "Denial of Service"),
    UNHANDLED_ERROR("Unhandled Error / Stack Trace", "Information Disclosure"),
    GET_MUTATION("GET-based Mutation", "Method Handling"),
    ENGINE_FINGERPRINT("Engine Fingerprinting", "Reconnaissance"),
    CLAIRVOYANCE("Clairvoyance Schema Oracle", "Schema Reconstruction");

    private final String displayName;
    private final String category;

    AuditProbeType_littlespidy(String displayName, String category) {
        this.displayName = displayName;
        this.category = category;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getCategory() {
        return category;
    }
}
