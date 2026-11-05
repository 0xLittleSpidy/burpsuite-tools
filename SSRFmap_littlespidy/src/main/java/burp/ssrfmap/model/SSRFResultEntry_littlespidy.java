// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.model;

import burp.api.montoya.http.message.HttpRequestResponse;

public class SSRFResultEntry_littlespidy {
    private final int id;
    private final String module;
    private final String scheme;
    private final String payload;
    private int statusCode;
    private int length;
    private long responseTimeMs;
    private String diffIndicator;
    private String collaboratorInfo;
    private String status;
    private HttpRequestResponse httpRequestResponse;
    private String baselineDiff;
    private String collaboratorInteractionDetails;

    public SSRFResultEntry_littlespidy(
            int id,
            String module,
            String scheme,
            String payload,
            int statusCode,
            int length,
            long responseTimeMs,
            String diffIndicator,
            String collaboratorInfo,
            String status,
            HttpRequestResponse httpRequestResponse,
            String baselineDiff) {
        this.id = id;
        this.module = module;
        this.scheme = scheme;
        this.payload = payload;
        this.statusCode = statusCode;
        this.length = length;
        this.responseTimeMs = responseTimeMs;
        this.diffIndicator = diffIndicator;
        this.collaboratorInfo = collaboratorInfo;
        this.status = status;
        this.httpRequestResponse = httpRequestResponse;
        this.baselineDiff = baselineDiff != null ? baselineDiff : "";
        this.collaboratorInteractionDetails = "";
    }

    public int getId() {
        return id;
    }

    public String getModule() {
        return module;
    }

    public String getScheme() {
        return scheme;
    }

    public String getPayload() {
        return payload;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public String getDiffIndicator() {
        return diffIndicator;
    }

    public void setDiffIndicator(String diffIndicator) {
        this.diffIndicator = diffIndicator;
    }

    public String getCollaboratorInfo() {
        return collaboratorInfo;
    }

    public void setCollaboratorInfo(String collaboratorInfo) {
        this.collaboratorInfo = collaboratorInfo;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }

    public void setHttpRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }

    public String getBaselineDiff() {
        return baselineDiff;
    }

    public void setBaselineDiff(String baselineDiff) {
        this.baselineDiff = baselineDiff;
    }

    public String getCollaboratorInteractionDetails() {
        return collaboratorInteractionDetails;
    }

    public void setCollaboratorInteractionDetails(String collaboratorInteractionDetails) {
        this.collaboratorInteractionDetails = collaboratorInteractionDetails;
    }
}
