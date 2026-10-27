// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.model;

import java.util.Objects;

/**
 * Represents an extracted authentication token, header, or session cookie.
 */
public class AuthItem_littlespidy {

    private final String type;
    private final String name;
    private final String value;

    public AuthItem_littlespidy(String type, String name, String value) {
        this.type = type != null ? type : "";
        this.name = name != null ? name : "";
        this.value = value != null ? value : "";
    }

    public String getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public int getLength() {
        return value.length();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthItem_littlespidy that = (AuthItem_littlespidy) o;
        return Objects.equals(type, that.type) &&
                Objects.equals(name, that.name) &&
                Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, name, value);
    }

    @Override
    public String toString() {
        return "[" + type + "] " + name + " (" + getLength() + " chars)";
    }
}
