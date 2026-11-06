// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Model representing a parsed GWT-RPC server response.
 * Handles //OK success payloads and //EX serialized exception payloads.
 *
 * @author littlespidy
 */
public class GWTRpcResponse {

    public enum ResponseStatus {
        SUCCESS,
        EXCEPTION,
        UNKNOWN
    }

    private ResponseStatus status = ResponseStatus.UNKNOWN;
    private String rawResponse = "";
    private int streamVersion = -1;
    private int flags = 0;
    private final List<String> stringTable = new ArrayList<>();
    private final List<Object> payloadTokens = new ArrayList<>();
    private String returnType = "";
    private String exceptionType = "";
    private String exceptionMessage = "";
    private final List<String> extractedValues = new ArrayList<>();
    private String formattedSummary = "";
    private String parseError = "";

    public ResponseStatus getStatus() {
        return status;
    }

    public void setStatus(ResponseStatus status) {
        this.status = status;
    }

    public String getRawResponse() {
        return rawResponse;
    }

    public void setRawResponse(String rawResponse) {
        this.rawResponse = rawResponse != null ? rawResponse : "";
    }

    public int getStreamVersion() {
        return streamVersion;
    }

    public void setStreamVersion(int streamVersion) {
        this.streamVersion = streamVersion;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public List<String> getStringTable() {
        return stringTable;
    }

    public void setStringTable(List<String> entries) {
        this.stringTable.clear();
        if (entries != null) {
            this.stringTable.addAll(entries);
        }
    }

    public List<Object> getPayloadTokens() {
        return payloadTokens;
    }

    public void setPayloadTokens(List<Object> tokens) {
        this.payloadTokens.clear();
        if (tokens != null) {
            this.payloadTokens.addAll(tokens);
        }
    }

    public String getReturnType() {
        return returnType;
    }

    public void setReturnType(String returnType) {
        this.returnType = returnType != null ? returnType : "";
    }

    public String getExceptionType() {
        return exceptionType;
    }

    public void setExceptionType(String exceptionType) {
        this.exceptionType = exceptionType != null ? exceptionType : "";
    }

    public String getExceptionMessage() {
        return exceptionMessage;
    }

    public void setExceptionMessage(String exceptionMessage) {
        this.exceptionMessage = exceptionMessage != null ? exceptionMessage : "";
    }

    public List<String> getExtractedValues() {
        return extractedValues;
    }

    public void addExtractedValue(String val) {
        if (val != null && !val.isEmpty()) {
            this.extractedValues.add(val);
        }
    }

    public String getFormattedSummary() {
        return formattedSummary;
    }

    public void setFormattedSummary(String formattedSummary) {
        this.formattedSummary = formattedSummary != null ? formattedSummary : "";
    }

    public String getParseError() {
        return parseError;
    }

    public void setParseError(String parseError) {
        this.parseError = parseError != null ? parseError : "";
    }

    public boolean isSuccess() {
        return status == ResponseStatus.SUCCESS;
    }

    public boolean isException() {
        return status == ResponseStatus.EXCEPTION;
    }
}
