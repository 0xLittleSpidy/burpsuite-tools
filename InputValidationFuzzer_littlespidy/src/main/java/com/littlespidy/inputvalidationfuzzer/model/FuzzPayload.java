package com.littlespidy.inputvalidationfuzzer.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable representation of a single input validation test payload.
 *
 * @author littlespidy
 */
public record FuzzPayload(
    String name,
    String value,
    String detail,
    boolean isDefault
) {
    public FuzzPayload(String name, String value, String detail) {
        this(name, value, detail, true);
    }
}
