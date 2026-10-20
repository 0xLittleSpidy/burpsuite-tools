// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.model;

import java.util.Objects;

public class OAuthParam {

    public enum ParamLocation {
        QUERY("URL Query"),
        BODY("Body"),
        HEADER("Header"),
        COOKIE("Cookie"),
        UNKNOWN("Unknown");

        private final String label;

        ParamLocation(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    private final String name;
    private final String rawValue;
    private final String decodedValue;
    private final ParamLocation location;
    private final String description;
    private final boolean standard;
    private final boolean sensitive;

    public OAuthParam(String name, String rawValue, String decodedValue, ParamLocation location,
                      String description, boolean standard, boolean sensitive) {
        this.name = name != null ? name : "";
        this.rawValue = rawValue != null ? rawValue : "";
        this.decodedValue = decodedValue != null ? decodedValue : this.rawValue;
        this.location = location != null ? location : ParamLocation.UNKNOWN;
        this.description = description != null ? description : "";
        this.standard = standard;
        this.sensitive = sensitive;
    }

    public String getName() {
        return name;
    }

    public String getRawValue() {
        return rawValue;
    }

    public String getDecodedValue() {
        return decodedValue;
    }

    public ParamLocation getLocation() {
        return location;
    }

    public String getDescription() {
        return description;
    }

    public boolean isStandard() {
        return standard;
    }

    public boolean isSensitive() {
        return sensitive;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OAuthParam that)) return false;
        return Objects.equals(name, that.name) && location == that.location;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, location);
    }
}
