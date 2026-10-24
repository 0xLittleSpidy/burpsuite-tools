// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.model;

/**
 * Represents an individual Burp Suite extension in the catalog.
 */
public class ExtensionItem_littlespidy {

    public enum Status {
        IDLE("Idle"),
        CONNECTING("Connecting..."),
        DOWNLOADING("Downloading"),
        COMPLETED("Completed"),
        FAILED("Failed"),
        CANCELLED("Cancelled");

        private final String display;

        Status(String display) {
            this.display = display;
        }

        public String getDisplay() {
            return display;
        }
    }

    private final String id;
    private final String name;
    private final String category;
    private final String jarFileName;
    private final String downloadUrl;
    private final String estimatedSize;
    private final String description;

    private boolean selected;
    private Status status;
    private int progressPercent;
    private String statusMessage;

    public ExtensionItem_littlespidy(String id, String name, String category, String jarFileName,
                                     String downloadUrl, String estimatedSize, String description) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.jarFileName = jarFileName;
        this.downloadUrl = downloadUrl;
        this.estimatedSize = estimatedSize;
        this.description = description;
        this.selected = true;
        this.status = Status.IDLE;
        this.progressPercent = 0;
        this.statusMessage = Status.IDLE.getDisplay();
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getCategory() {
        return category;
    }

    public String getJarFileName() {
        return jarFileName;
    }

    public String getDownloadUrl() {
        return downloadUrl;
    }

    public String getEstimatedSize() {
        return estimatedSize;
    }

    public String getDescription() {
        return description;
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
        this.statusMessage = status.getDisplay();
    }

    public int getProgressPercent() {
        return progressPercent;
    }

    public void setProgressPercent(int progressPercent) {
        this.progressPercent = Math.max(0, Math.min(100, progressPercent));
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public void reset() {
        this.status = Status.IDLE;
        this.progressPercent = 0;
        this.statusMessage = Status.IDLE.getDisplay();
    }
}
