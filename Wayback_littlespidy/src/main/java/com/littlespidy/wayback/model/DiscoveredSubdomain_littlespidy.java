// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.model;

import java.util.Objects;

public class DiscoveredSubdomain_littlespidy {

    private String subdomain;
    private int pathCount;
    private String status;

    public DiscoveredSubdomain_littlespidy() {
        this.subdomain = "";
        this.pathCount = 0;
        this.status = "Discovered";
    }

    public DiscoveredSubdomain_littlespidy(String subdomain, int pathCount) {
        this.subdomain = subdomain != null ? subdomain.trim() : "";
        this.pathCount = pathCount;
        this.status = "Discovered";
    }

    public DiscoveredSubdomain_littlespidy(String subdomain, int pathCount, String status) {
        this.subdomain = subdomain != null ? subdomain.trim() : "";
        this.pathCount = pathCount;
        this.status = status != null ? status : "Discovered";
    }

    public String getSubdomain() {
        return subdomain;
    }

    public synchronized int getPathCount() {
        return pathCount;
    }

    public synchronized void setPathCount(int pathCount) {
        this.pathCount = pathCount;
    }

    public synchronized String getStatus() {
        return status;
    }

    public synchronized void setStatus(String status) {
        this.status = status;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DiscoveredSubdomain_littlespidy that = (DiscoveredSubdomain_littlespidy) o;
        return Objects.equals(subdomain, that.subdomain);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subdomain);
    }
}
