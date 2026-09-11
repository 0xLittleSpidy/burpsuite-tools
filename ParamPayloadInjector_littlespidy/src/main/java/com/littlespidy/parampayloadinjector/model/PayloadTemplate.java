package com.littlespidy.parampayloadinjector.model;

import java.util.Objects;
import java.util.Random;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Model representing a parameterized payload template with placeholder substitution.
 */
public class PayloadTemplate {
    private String id;
    private String category;
    private String name;
    private String template;
    private String description;
    private boolean enabled;

    private static final String CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final Random RNG = new Random();

    public PayloadTemplate(String id, String category, String name, String template, String description, boolean enabled) {
        this.id = id;
        this.category = category;
        this.name = name;
        this.template = template;
        this.description = description;
        this.enabled = enabled;
    }

    public String getId() {
        return id;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
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

    /**
     * Renders the template replacing placeholders:
     * {param}  -> parameter name
     * {value}  -> original parameter value
     * {rand}   -> random 5-character alphanumeric token
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
        PayloadTemplate that = (PayloadTemplate) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
