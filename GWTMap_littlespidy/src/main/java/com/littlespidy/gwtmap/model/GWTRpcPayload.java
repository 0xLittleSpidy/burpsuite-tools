// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import java.util.*;

/**
 * Encapsulates a fully deserialized GWT-RPC wire request payload,
 * its header properties, string table, parameter AST nodes, and fuzzable offsets.
 *
 * @author littlespidy
 */
public class GWTRpcPayload {

    private String rawPayload = "";
    private int streamVersion = 7;
    private int flags = 0;
    private int stringTableLength = 0;
    private String baseUrl = "";
    private String strongName = "";
    private String serviceInterface = "";
    private String methodName = "";

    // XSRF Token support (FLAG_RPC_TOKEN_INCLUDED = 0x2)
    private boolean hasXsrfToken = false;
    private String xsrfTokenName = "";
    private String xsrfTokenValue = "";

    private final List<GWTRpcParameter> parameters = new ArrayList<>();
    private final List<String> stringTable = new ArrayList<>();
    private final List<Integer> indexTable = new ArrayList<>();
    private final Map<Integer, String> fuzzableIndices = new LinkedHashMap<>();

    public GWTRpcPayload() {}

    public String getRawPayload() {
        return rawPayload;
    }

    public void setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload != null ? rawPayload : "";
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
        this.hasXsrfToken = (flags & 0x2) != 0;
    }

    public int getStringTableLength() {
        return stringTableLength;
    }

    public void setStringTableLength(int stringTableLength) {
        this.stringTableLength = stringTableLength;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl != null ? baseUrl : "";
    }

    public String getStrongName() {
        return strongName;
    }

    public void setStrongName(String strongName) {
        this.strongName = strongName != null ? strongName : "";
    }

    public String getServiceInterface() {
        return serviceInterface;
    }

    public void setServiceInterface(String serviceInterface) {
        this.serviceInterface = serviceInterface != null ? serviceInterface : "";
    }

    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName != null ? methodName : "";
    }

    public boolean hasXsrfToken() {
        return hasXsrfToken;
    }

    public String getXsrfTokenName() {
        return xsrfTokenName;
    }

    public void setXsrfTokenName(String xsrfTokenName) {
        this.xsrfTokenName = xsrfTokenName != null ? xsrfTokenName : "";
    }

    public String getXsrfTokenValue() {
        return xsrfTokenValue;
    }

    public void setXsrfTokenValue(String xsrfTokenValue) {
        this.xsrfTokenValue = xsrfTokenValue != null ? xsrfTokenValue : "";
    }

    public List<GWTRpcParameter> getParameters() {
        return Collections.unmodifiableList(parameters);
    }

    public void addParameter(GWTRpcParameter parameter) {
        if (parameter != null) {
            parameters.add(parameter);
        }
    }

    public List<String> getStringTable() {
        return Collections.unmodifiableList(stringTable);
    }

    public void setStringTable(List<String> strings) {
        stringTable.clear();
        if (strings != null) {
            stringTable.addAll(strings);
        }
    }

    public List<Integer> getIndexTable() {
        return Collections.unmodifiableList(indexTable);
    }

    public void setIndexTable(List<Integer> indices) {
        indexTable.clear();
        if (indices != null) {
            indexTable.addAll(indices);
        }
    }

    public Map<Integer, String> getFuzzableIndices() {
        return Collections.unmodifiableMap(fuzzableIndices);
    }

    public void markFuzzable(int indexInPipeList, String type) {
        fuzzableIndices.put(indexInPipeList, type);
    }
}
