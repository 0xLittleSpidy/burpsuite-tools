// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import java.util.Objects;
import java.util.Random;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Model representing a parameterized payload template with placeholder substitution.
 * Used for XSS, CSTI, and SQL injection tabs.
 *
 * Supported placeholders:
 *   {param} -> current parameter name
 *   {value} -> original parameter value
 *   {rand}  -> random 5-character alphanumeric token
 *
 * @author littlespidy
 */
public class ParamPayloadEntry {
    private String id;
    private String name;
    private String template;
    private String description;
    private boolean enabled;
    private String sourceType;
    private String sourceFile;

    private static final String CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final Random RNG = new Random();

    public ParamPayloadEntry(String id, String name, String template, String description, boolean enabled) {
        this(id, name, template, description, enabled, "Manual", "N/A");
    }

    public ParamPayloadEntry(String id, String name, String template, String description, boolean enabled, String sourceType, String sourceFile) {
        this.id = id != null ? id : "";
        this.name = name != null ? name : "";
        this.template = template != null ? template : "";
        this.description = description != null ? description : "";
        this.enabled = enabled;
        this.sourceType = (sourceType != null && !sourceType.isBlank()) ? sourceType : "Manual";
        this.sourceFile = (sourceFile != null && !sourceFile.isBlank()) ? sourceFile : "N/A";
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
        this.name = name;
    }

    public String getTemplate() {
        return template;
    }

    public void setTemplate(String template) {
        this.template = template;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = (sourceType != null && !sourceType.isBlank()) ? sourceType : "Manual";
    }

    public String getSourceFile() {
        return sourceFile;
    }

    public void setSourceFile(String sourceFile) {
        this.sourceFile = (sourceFile != null && !sourceFile.isBlank()) ? sourceFile : "N/A";
    }

    /**
     * Renders the template replacing placeholders:
     *   {param} -> parameter name
     *   {value} -> original parameter value
     *   {rand}  -> random 5-character alphanumeric token
     */
    public String render(String paramName, String originalValue) {
        String safeParam = (paramName == null) ? "" : paramName;
        String safeValue = (originalValue == null) ? "" : originalValue;
        String randToken = generateRandomToken(5);

        String result = template;
        result = result.replace("{param}", safeParam);
        result = result.replace("{value}", safeValue);
        result = result.replace("{rand}", randToken);
        return result;
    }

    private static String generateRandomToken(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARS.charAt(RNG.nextInt(CHARS.length())));
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ParamPayloadEntry that = (ParamPayloadEntry) o;
        return Objects.equals(id, that.id) || (Objects.equals(name, that.name) && Objects.equals(template, that.template));
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, template);
    }
}
