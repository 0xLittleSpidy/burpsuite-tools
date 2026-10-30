// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Model representing the outcome of a POST-to-GET method tampering probe.
 */
public class PostToGetTestResult_littlespidy {

    private final int id;
    private final String collectionId;
    private final String collectionName;
    private final String path;
    private final String fullUrl;
    private final String originalMethod;
    private final String mutatedMethod;
    private final String convertedQueryParams;
    private final int originalStatusCode;
    private final int mutatedStatusCode;
    private final int originalResponseLength;
    private final int mutatedResponseLength;
    private final String verdict;
    private final long timestamp;

    private HttpRequestResponse originalReqResp;
    private HttpRequestResponse mutatedReqResp;

    private byte[] originalRequestBytes;
    private byte[] originalResponseBytes;
    private byte[] mutatedRequestBytes;
    private byte[] mutatedResponseBytes;

    public PostToGetTestResult_littlespidy(
            int id, String collectionId, String collectionName,
            String path, String fullUrl,
            String originalMethod, String mutatedMethod,
            String convertedQueryParams,
            int originalStatusCode, int mutatedStatusCode,
            int originalResponseLength, int mutatedResponseLength,
            String verdict,
            HttpRequestResponse originalReqResp,
            HttpRequestResponse mutatedReqResp) {
        this.id = id;
        this.collectionId = collectionId != null ? collectionId : "";
        this.collectionName = collectionName != null ? collectionName : "";
        this.path = path != null ? path : "/";
        this.fullUrl = fullUrl != null ? fullUrl : "";
        this.originalMethod = originalMethod != null ? originalMethod : "POST";
        this.mutatedMethod = mutatedMethod != null ? mutatedMethod : "GET";
        this.convertedQueryParams = convertedQueryParams != null ? convertedQueryParams : "";
        this.originalStatusCode = originalStatusCode;
        this.mutatedStatusCode = mutatedStatusCode;
        this.originalResponseLength = originalResponseLength;
        this.mutatedResponseLength = mutatedResponseLength;
        this.verdict = verdict != null ? verdict : "";
        this.originalReqResp = originalReqResp;
        this.mutatedReqResp = mutatedReqResp;
        this.timestamp = System.currentTimeMillis();

        if (originalReqResp != null) {
            if (originalReqResp.request() != null) {
                this.originalRequestBytes = originalReqResp.request().toByteArray().getBytes();
            }
            if (originalReqResp.hasResponse() && originalReqResp.response() != null) {
                this.originalResponseBytes = originalReqResp.response().toByteArray().getBytes();
            }
        }
        if (mutatedReqResp != null) {
            if (mutatedReqResp.request() != null) {
                this.mutatedRequestBytes = mutatedReqResp.request().toByteArray().getBytes();
            }
            if (mutatedReqResp.hasResponse() && mutatedReqResp.response() != null) {
                this.mutatedResponseBytes = mutatedReqResp.response().toByteArray().getBytes();
            }
        }
    }

    public int getId() { return id; }
    public String getCollectionId() { return collectionId; }
    public String getCollectionName() { return collectionName; }
    public String getPath() { return path; }
    public String getFullUrl() { return fullUrl; }
    public String getOriginalMethod() { return originalMethod; }
    public String getMutatedMethod() { return mutatedMethod; }
    public String getConvertedQueryParams() { return convertedQueryParams; }
    public int getOriginalStatusCode() { return originalStatusCode; }
    public int getMutatedStatusCode() { return mutatedStatusCode; }
    public int getOriginalResponseLength() { return originalResponseLength; }
    public int getMutatedResponseLength() { return mutatedResponseLength; }
    public String getVerdict() { return verdict; }
    public long getTimestamp() { return timestamp; }

    public HttpRequestResponse getOriginalReqResp() { return originalReqResp; }
    public void setOriginalReqResp(HttpRequestResponse reqResp) { this.originalReqResp = reqResp; }

    public HttpRequestResponse getMutatedReqResp() { return mutatedReqResp; }
    public void setMutatedReqResp(HttpRequestResponse reqResp) { this.mutatedReqResp = reqResp; }

    public byte[] getOriginalRequestBytes() { return originalRequestBytes; }
    public void setOriginalRequestBytes(byte[] b) { this.originalRequestBytes = b; }

    public byte[] getOriginalResponseBytes() { return originalResponseBytes; }
    public void setOriginalResponseBytes(byte[] b) { this.originalResponseBytes = b; }

    public byte[] getMutatedRequestBytes() { return mutatedRequestBytes; }
    public void setMutatedRequestBytes(byte[] b) { this.mutatedRequestBytes = b; }

    public byte[] getMutatedResponseBytes() { return mutatedResponseBytes; }
    public void setMutatedResponseBytes(byte[] b) { this.mutatedResponseBytes = b; }
}
