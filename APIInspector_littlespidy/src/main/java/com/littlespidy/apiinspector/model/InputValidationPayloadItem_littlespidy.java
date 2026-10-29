// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Representation of an individual input validation fuzzing payload item.
 * Displays as an individual row in the Input Validation Config tab.
 */
public class InputValidationPayloadItem_littlespidy {

    private final String id;
    private final String category;
    private final String payload;
    private final List<String> detectionSignatures;
    private final String description;
    private boolean enabled;
    private final boolean blns;
    private final boolean custom;

    public InputValidationPayloadItem_littlespidy(
            String id,
            String category,
            String payload,
            List<String> detectionSignatures,
            String description,
            boolean enabled,
            boolean blns,
            boolean custom) {
        this.id = id != null ? id : "";
        this.category = category != null ? category : "";
        this.payload = payload != null ? payload : "";
        this.detectionSignatures = detectionSignatures != null ? new ArrayList<>(detectionSignatures) : new ArrayList<>();
        this.description = description != null ? description : "";
        this.enabled = enabled;
        this.blns = blns;
        this.custom = custom;
    }

    public InputValidationPayloadItem_littlespidy(
            String id,
            String category,
            String payload,
            List<String> detectionSignatures,
            String description) {
        this(id, category, payload, detectionSignatures, description, true, id != null && id.startsWith("blns_"), false);
    }

    public String getId() {
        return id;
    }

    public String getCategory() {
        return category;
    }

    public String getPayload() {
        return payload;
    }

    public List<String> getDetectionSignatures() {
        return Collections.unmodifiableList(detectionSignatures);
    }

    public String getDetectionSignaturesSummary() {
        if (detectionSignatures.isEmpty()) {
            return description;
        }
        return String.join(", ", detectionSignatures);
    }

    public String getDescription() {
        return description;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isBlns() {
        return blns;
    }

    public boolean isCustom() {
        return custom;
    }
}
