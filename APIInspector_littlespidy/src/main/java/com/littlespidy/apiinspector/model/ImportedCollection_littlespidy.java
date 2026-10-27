// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents an imported API specification or Postman collection.
 */
public class ImportedCollection_littlespidy {

    private String id;
    private String name;
    private String formatType;
    private String sourceType;
    private String sourceLocation;
    private String targetBaseUrl;
    private String importStatus;
    private String statusMessage;
    private long importedAt;
    private String assignedProfileId;
    private List<DiscoveredEndpoint_littlespidy> endpoints;
    private java.util.Map<String, String> tagDescriptions;

    public ImportedCollection_littlespidy() {
        this.id = UUID.randomUUID().toString();
        this.name = "Untitled Collection";
        this.formatType = "OpenAPI 3.0";
        this.sourceType = "FILE";
        this.sourceLocation = "";
        this.targetBaseUrl = "";
        this.importStatus = "Ready";
        this.statusMessage = "";
        this.importedAt = System.currentTimeMillis();
        this.assignedProfileId = null;
        this.endpoints = new ArrayList<>();
        this.tagDescriptions = new java.util.LinkedHashMap<>();
    }

    public ImportedCollection_littlespidy(String name, String formatType, String sourceType, String sourceLocation) {
        this();
        this.name = name != null && !name.isBlank() ? name : "Untitled Collection";
        this.formatType = formatType != null ? formatType : "OpenAPI 3.0";
        this.sourceType = sourceType != null ? sourceType : "FILE";
        this.sourceLocation = sourceLocation != null ? sourceLocation : "";
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name : "";
    }

    public String getFormatType() {
        return formatType;
    }

    public void setFormatType(String formatType) {
        this.formatType = formatType != null ? formatType : "";
    }

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = sourceType != null ? sourceType : "FILE";
    }

    public String getSourceLocation() {
        return sourceLocation;
    }

    public void setSourceLocation(String sourceLocation) {
        this.sourceLocation = sourceLocation != null ? sourceLocation : "";
    }

    public String getTargetBaseUrl() {
        return targetBaseUrl;
    }

    public void setTargetBaseUrl(String targetBaseUrl) {
        this.targetBaseUrl = targetBaseUrl != null ? targetBaseUrl : "";
    }

    public String getImportStatus() {
        return importStatus;
    }

    public void setImportStatus(String importStatus) {
        this.importStatus = importStatus != null ? importStatus : "Ready";
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage != null ? statusMessage : "";
    }

    public long getImportedAt() {
        return importedAt;
    }

    public void setImportedAt(long importedAt) {
        this.importedAt = importedAt;
    }

    public String getAssignedProfileId() {
        return assignedProfileId;
    }

    public void setAssignedProfileId(String assignedProfileId) {
        this.assignedProfileId = assignedProfileId;
    }

    public List<DiscoveredEndpoint_littlespidy> getEndpoints() {
        if (endpoints == null) endpoints = new ArrayList<>();
        return endpoints;
    }

    public void setEndpoints(List<DiscoveredEndpoint_littlespidy> endpoints) {
        this.endpoints = endpoints != null ? endpoints : new ArrayList<>();
    }

    public int getEndpointCount() {
        return endpoints != null ? endpoints.size() : 0;
    }

    public java.util.Map<String, String> getTagDescriptions() {
        if (tagDescriptions == null) {
            tagDescriptions = new java.util.LinkedHashMap<>();
        }
        return tagDescriptions;
    }

    public void setTagDescriptions(java.util.Map<String, String> tagDescriptions) {
        this.tagDescriptions = tagDescriptions != null ? new java.util.LinkedHashMap<>(tagDescriptions) : new java.util.LinkedHashMap<>();
    }

    @Override
    public String toString() {
        return name + " (" + formatType + ", " + getEndpointCount() + " endpoints)";
    }
}
