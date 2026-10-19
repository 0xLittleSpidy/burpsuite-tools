// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;

import java.util.ArrayList;
import java.util.List;

/**
 * Result container returned after attempting to parse an API definition.
 */
public class ParseResult_littlespidy {

    private boolean success;
    private ImportedCollection_littlespidy collection;
    private String errorMessage;
    private List<String> warnings;

    public ParseResult_littlespidy() {
        this.success = false;
        this.collection = null;
        this.errorMessage = "";
        this.warnings = new ArrayList<>();
    }

    public static ParseResult_littlespidy success(ImportedCollection_littlespidy collection) {
        ParseResult_littlespidy res = new ParseResult_littlespidy();
        res.success = true;
        res.collection = collection;
        return res;
    }

    public static ParseResult_littlespidy failure(String errorMessage) {
        ParseResult_littlespidy res = new ParseResult_littlespidy();
        res.success = false;
        res.errorMessage = errorMessage != null ? errorMessage : "Unknown parsing error";
        return res;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public ImportedCollection_littlespidy getCollection() {
        return collection;
    }

    public void setCollection(ImportedCollection_littlespidy collection) {
        this.collection = collection;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage != null ? errorMessage : "";
    }

    public List<String> getWarnings() {
        if (warnings == null) warnings = new ArrayList<>();
        return warnings;
    }

    public void addWarning(String warning) {
        if (warnings == null) warnings = new ArrayList<>();
        warnings.add(warning);
    }
}
