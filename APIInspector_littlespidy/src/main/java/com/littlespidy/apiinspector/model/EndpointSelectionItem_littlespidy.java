// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

/**
 * Endpoint selection container representing an endpoint from an imported API collection
 * that can be toggled for security testing (Auth Analyzer, CORS, Input Validation).
 */
public class EndpointSelectionItem_littlespidy {
    public final ImportedCollection_littlespidy collection;
    public final DiscoveredEndpoint_littlespidy endpoint;
    public boolean selected;

    public EndpointSelectionItem_littlespidy(
            ImportedCollection_littlespidy collection,
            DiscoveredEndpoint_littlespidy endpoint,
            boolean selected) {
        this.collection = collection;
        this.endpoint = endpoint;
        this.selected = selected;
    }

    public ImportedCollection_littlespidy getCollection() {
        return collection;
    }

    public DiscoveredEndpoint_littlespidy getEndpoint() {
        return endpoint;
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }
}
