package com.littlespidy.uploadscanner.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents the execution stage of an HTTP transaction in Upload Scanner.
 *
 * @author littlespidy
 */
public enum StageType {
    UPLOAD("Upload"),
    PREFLIGHT("Preflight"),
    REDOWNLOAD("ReDownload"),
    VERIFICATION("Verification");

    private final String displayName;

    StageType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
