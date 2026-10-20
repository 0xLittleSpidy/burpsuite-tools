// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import java.util.Objects;
import java.util.UUID;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Model representing a target file path entry used for Path Traversal payload substitutions.
 * Categorized into Linux or Windows environments with associated descriptions and categories.
 *
 * @author littlespidy
 */
public class FilePathEntry_littlespidy {

    private String id;
    private String path;
    private String category;
    private String description;
    private String platform;
    private boolean enabled;
    private String sourceType;
    private String sourceFile;

    public FilePathEntry_littlespidy() {
        this(UUID.randomUUID().toString(), "", "General", "", "Linux", true, "Default", "N/A");
    }

    public FilePathEntry_littlespidy(String id, String path, String category, String description,
                                    String platform, boolean enabled, String sourceType, String sourceFile) {
        this.id = (id != null && !id.isBlank()) ? id : UUID.randomUUID().toString();
        this.path = (path != null) ? path : "";
        this.category = (category != null && !category.isBlank()) ? category : "General";
        this.description = (description != null) ? description : "";
        this.platform = (platform != null && !platform.isBlank()) ? platform : "Linux";
        this.enabled = enabled;
        this.sourceType = (sourceType != null && !sourceType.isBlank()) ? sourceType : "Default";
        this.sourceFile = (sourceFile != null && !sourceFile.isBlank()) ? sourceFile : "N/A";
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = (path != null) ? path : "";
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = (category != null && !category.isBlank()) ? category : "General";
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = (description != null) ? description : "";
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = (platform != null && !platform.isBlank()) ? platform : "Linux";
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
        this.sourceType = (sourceType != null && !sourceType.isBlank()) ? sourceType : "Default";
    }

    public String getSourceFile() {
        return sourceFile;
    }

    public void setSourceFile(String sourceFile) {
        this.sourceFile = (sourceFile != null && !sourceFile.isBlank()) ? sourceFile : "N/A";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FilePathEntry_littlespidy that = (FilePathEntry_littlespidy) o;
        return Objects.equals(id, that.id) || (Objects.equals(path, that.path) && Objects.equals(platform, that.platform));
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, path, platform);
    }
}
