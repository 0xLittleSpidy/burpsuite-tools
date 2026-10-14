// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import java.util.Objects;

/**
 * Represents an enumerated GWT RPC service endpoint and its associated
 * serialization policy strong name.
 *
 * @author littlespidy
 */
public class GWTService {

    private final String servicePath;
    private final String strongName;
    private int methodCount = 0;

    public GWTService(String servicePath, String strongName) {
        this.servicePath = servicePath != null ? servicePath : "Unknown";
        this.strongName = strongName != null ? strongName : "Unknown";
    }

    public String getServicePath() {
        return servicePath;
    }

    public String getStrongName() {
        return strongName;
    }

    public int getMethodCount() {
        return methodCount;
    }

    public void setMethodCount(int methodCount) {
        this.methodCount = methodCount;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GWTService that = (GWTService) o;
        return Objects.equals(servicePath, that.servicePath) && Objects.equals(strongName, that.strongName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(servicePath, strongName);
    }

    @Override
    public String toString() {
        return servicePath + " (" + strongName + ")";
    }
}
