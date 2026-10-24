// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.model;

import java.util.Objects;

public class DiscoveredPath_littlespidy {

    private String host;
    private String path;
    private String status;
    private String result;
    private int statusCode;
    private String lastTestedProtocol;
    private int contentLength;

    public DiscoveredPath_littlespidy() {
        this.host = "";
        this.path = "";
        this.status = "Pending";
        this.result = "-";
        this.statusCode = 0;
        this.lastTestedProtocol = "-";
        this.contentLength = 0;
    }

    public DiscoveredPath_littlespidy(String host, String path) {
        this.host = host != null ? host.trim() : "";
        this.path = path != null ? path.trim() : "";
        this.status = "Pending";
        this.result = "-";
        this.statusCode = 0;
        this.lastTestedProtocol = "-";
        this.contentLength = 0;
    }

    public DiscoveredPath_littlespidy(String host, String path, String status, String result, int statusCode, String lastTestedProtocol, int contentLength) {
        this.host = host != null ? host.trim() : "";
        this.path = path != null ? path.trim() : "";
        this.status = status != null ? status : "Pending";
        this.result = result != null ? result : "-";
        this.statusCode = statusCode;
        this.lastTestedProtocol = lastTestedProtocol != null ? lastTestedProtocol : "-";
        this.contentLength = contentLength;
    }

    public String getHost() {
        return host;
    }

    public String getPath() {
        return path;
    }

    public synchronized String getStatus() {
        return status;
    }

    public synchronized void setStatus(String status) {
        this.status = status;
    }

    public synchronized String getResult() {
        return result;
    }

    public synchronized void setResult(String result) {
        this.result = result;
    }

    public synchronized int getStatusCode() {
        return statusCode;
    }

    public synchronized void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public synchronized String getLastTestedProtocol() {
        return lastTestedProtocol;
    }

    public synchronized void setLastTestedProtocol(String lastTestedProtocol) {
        this.lastTestedProtocol = lastTestedProtocol;
    }

    public synchronized int getContentLength() {
        return contentLength;
    }

    public synchronized void setContentLength(int contentLength) {
        this.contentLength = contentLength;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DiscoveredPath_littlespidy that = (DiscoveredPath_littlespidy) o;
        return Objects.equals(host, that.host) && Objects.equals(path, that.path);
    }

    @Override
    public int hashCode() {
        return Objects.hash(host, path);
    }
}
