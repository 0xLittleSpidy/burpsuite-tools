package com.littlespidy.uploadscanner.model;

import java.nio.charset.StandardCharsets;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Defines an upload attack payload and its associated metadata.
 *
 * @author littlespidy
 */
public class PayloadDefinition {
    private final String name;
    private final String category;
    private final String filename;
    private final String contentType;
    private final byte[] content;
    private final String executionMarker;
    private final String collaboratorSubdomain;
    private final boolean isOob;

    public PayloadDefinition(String name,
                             String category,
                             String filename,
                             String contentType,
                             byte[] content,
                             String executionMarker) {
        this(name, category, filename, contentType, content, executionMarker, "", false);
    }

    public PayloadDefinition(String name,
                             String category,
                             String filename,
                             String contentType,
                             String contentString,
                             String executionMarker) {
        this(name, category, filename, contentType,
                contentString != null ? contentString.getBytes(StandardCharsets.UTF_8) : new byte[0],
                executionMarker, "", false);
    }

    public PayloadDefinition(String name,
                             String category,
                             String filename,
                             String contentType,
                             byte[] content,
                             String executionMarker,
                             String collaboratorSubdomain,
                             boolean isOob) {
        this.name = name;
        this.category = category;
        this.filename = filename;
        this.contentType = contentType;
        this.content = content != null ? content : new byte[0];
        this.executionMarker = executionMarker != null ? executionMarker : "";
        this.collaboratorSubdomain = collaboratorSubdomain != null ? collaboratorSubdomain : "";
        this.isOob = isOob;
    }

    public PayloadDefinition(String name,
                             String category,
                             String filename,
                             String contentType,
                             String contentString,
                             String executionMarker,
                             String collaboratorSubdomain,
                             boolean isOob) {
        this(name, category, filename, contentType,
                contentString != null ? contentString.getBytes(StandardCharsets.UTF_8) : new byte[0],
                executionMarker, collaboratorSubdomain, isOob);
    }

    public String getName() {
        return name;
    }

    public String getCategory() {
        return category;
    }

    public String getFilename() {
        return filename;
    }

    public String getContentType() {
        return contentType;
    }

    public byte[] getContent() {
        return content.clone();
    }

    public String getExecutionMarker() {
        return executionMarker;
    }

    public String getCollaboratorSubdomain() {
        return collaboratorSubdomain;
    }

    public boolean isOob() {
        return isOob;
    }
}
