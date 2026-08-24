package com.littlespidy.convertposttoget.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents a custom header or auth token to inject into attack requests.
 *
 * @author littlespidy
 */
public record ConfiguredHeader(
    String name,
    String value
) {
    public static ConfiguredHeader parse(String line) {
        if (line == null || line.trim().isEmpty()) return null;
        int colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
            String name = line.substring(0, colonIdx).trim();
            String value = line.substring(colonIdx + 1).trim();
            if (!name.isEmpty()) {
                return new ConfiguredHeader(name, value);
            }
        }
        return null;
    }
}
