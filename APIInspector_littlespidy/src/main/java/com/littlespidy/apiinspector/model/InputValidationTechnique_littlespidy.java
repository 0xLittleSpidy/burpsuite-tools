// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Representation of an input validation fuzzing technique / category.
 */
public class InputValidationTechnique_littlespidy {

    private final String id;
    private final String category;
    private final String description;
    private final List<String> samplePayloads;
    private final List<String> errorSignatures;
    private boolean enabled;

    public InputValidationTechnique_littlespidy(
            String id, String category, String description,
            List<String> samplePayloads, List<String> errorSignatures, boolean enabled) {
        this.id = id;
        this.category = category;
        this.description = description;
        this.samplePayloads = samplePayloads != null ? samplePayloads : new ArrayList<>();
        this.errorSignatures = errorSignatures != null ? errorSignatures : new ArrayList<>();
        this.enabled = enabled;
    }

    public InputValidationTechnique_littlespidy(
            String id, String category, String description,
            List<String> samplePayloads, List<String> errorSignatures) {
        this(id, category, description, samplePayloads, errorSignatures, true);
    }

    public String getId() {
        return id;
    }

    public String getCategory() {
        return category;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getSamplePayloads() {
        return samplePayloads;
    }

    public List<String> getErrorSignatures() {
        return errorSignatures;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getPayloadCount() {
        return samplePayloads.size();
    }

    public boolean isBlns() {
        return id != null && id.startsWith("blns_");
    }

    /**
     * Default list of input validation categories and payloads, loaded
     * from the JSON category definitions and Big List of Naughty Strings wordlist.
     */
    public static List<InputValidationTechnique_littlespidy> getDefaultTechniques() {
        return NaughtyStringsParser_littlespidy.loadDefaultBlnsTechniques();
    }
}
