// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a parsed parameter node in a deserialized GWT-RPC method call AST.
 *
 * @author littlespidy
 */
public class GWTRpcParameter {

    private final String typename;
    private final String cleanTypename;
    private final List<Object> values = new ArrayList<>();
    private final List<Integer> fuzzableIndices = new ArrayList<>();

    private boolean numeric = false;
    private boolean stringType = false;
    private boolean customObject = false;
    private boolean list = false;
    private boolean array = false;

    public GWTRpcParameter(String typename) {
        this.typename = typename != null ? typename : "Unknown";
        this.cleanTypename = extractCleanTypename(this.typename);
    }

    private static String extractCleanTypename(String raw) {
        if (raw == null) return "Unknown";
        int slash = raw.indexOf('/');
        return (slash != -1) ? raw.substring(0, slash) : raw;
    }

    public String getTypename() {
        return typename;
    }

    public String getCleanTypename() {
        return cleanTypename;
    }

    public List<Object> getValues() {
        return Collections.unmodifiableList(values);
    }

    public void addValue(Object value) {
        values.add(value);
    }

    public List<Integer> getFuzzableIndices() {
        return Collections.unmodifiableList(fuzzableIndices);
    }

    public void addFuzzableIndex(int idx) {
        if (!fuzzableIndices.contains(idx)) {
            fuzzableIndices.add(idx);
        }
    }

    public boolean isNumeric() {
        return numeric;
    }

    public void setNumeric(boolean numeric) {
        this.numeric = numeric;
    }

    public boolean isStringType() {
        return stringType;
    }

    public void setStringType(boolean stringType) {
        this.stringType = stringType;
    }

    public boolean isCustomObject() {
        return customObject;
    }

    public void setCustomObject(boolean customObject) {
        this.customObject = customObject;
    }

    public boolean isList() {
        return list;
    }

    public void setList(boolean list) {
        this.list = list;
    }

    public boolean isArray() {
        return array;
    }

    public void setArray(boolean array) {
        this.array = array;
    }

    @Override
    public String toString() {
        return cleanTypename + " = " + values;
    }
}
