// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.inputvalidation;

/**
 * Representation of an individual fuzzing payload from the Big List of Naughty Strings or custom definitions.
 */
public class InputValidationPayload_littlespidy {

    private final String id;
    private final String category;
    private final String name;
    private final String value;
    private final String description;
    private boolean enabled;
    private final boolean defaultEssential;

    public InputValidationPayload_littlespidy(
            String id,
            String category,
            String name,
            String value,
            String description,
            boolean enabled,
            boolean defaultEssential
    ) {
        this.id = id;
        this.category = category;
        this.name = name;
        this.value = value;
        this.description = description;
        this.enabled = enabled;
        this.defaultEssential = defaultEssential;
    }

    public String getId() {
        return id;
    }

    public String getCategory() {
        return category;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
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

    public boolean isDefaultEssential() {
        return defaultEssential;
    }
}
