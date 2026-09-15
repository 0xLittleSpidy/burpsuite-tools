// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Enum representing HTTP message header direction: Request or Response.
 *
 * @author littlespidy
 */
public enum HeaderType {
    REQUEST("Request"),
    RESPONSE("Response");

    private final String display;

    HeaderType(String display) {
        this.display = display;
    }

    public String display() {
        return display;
    }

    @Override
    public String toString() {
        return display;
    }
}
