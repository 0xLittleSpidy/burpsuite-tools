// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

/**
 * Result of on-demand active .map probing.
 *
 * @author littlespidy
 */
public enum ActiveProbeStatus {
    NOT_RUN("-"),
    PROBING("Probing..."),
    PASS("Pass (200 OK)"),
    FAIL("Fail (404/Error)");

    private final String label;

    ActiveProbeStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public boolean isPass() {
        return this == PASS;
    }

    public boolean isRun() {
        return this == PASS || this == FAIL;
    }
}
