// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.util.UUID;

/**
 * Encapsulates the results of an authentication test against an API endpoint,
 * including both authenticated and unauthenticated comparison responses.
 */
public class AuthTestResult_littlespidy {

    private String id;
    private String collectionId;
    private String collectionName;
    private String method;
    private String path;
    private String fullUrl;
    private String profileId;
    private String profileName;

    // Authenticated Request outcome
    private int authStatusCode;
    private int authResponseLength;
    private long authLatencyMs;

    // Unauthenticated Comparison outcome (if executed)
    private int unauthStatusCode;
    private int unauthResponseLength;
    private long unauthLatencyMs;

    // Classification & Evidence
    private AuthTestOutcome_littlespidy outcome;
    private String errorMessage;
    private long timestamp;

    // HTTP message bytes for inspector viewers
    private byte[] authRequestBytes;
    private byte[] authResponseBytes;
    private byte[] unauthRequestBytes;
    private byte[] unauthResponseBytes;

    public AuthTestResult_littlespidy() {
        this.id = UUID.randomUUID().toString();
        this.collectionId = "";
        this.collectionName = "";
        this.method = "GET";
        this.path = "/";
        this.fullUrl = "";
        this.profileId = "";
        this.profileName = "[None]";
        this.authStatusCode = 0;
        this.authResponseLength = 0;
        this.authLatencyMs = 0;
        this.unauthStatusCode = 0;
        this.unauthResponseLength = 0;
        this.unauthLatencyMs = 0;
        this.outcome = AuthTestOutcome_littlespidy.SUCCESS;
        this.errorMessage = "";
        this.timestamp = System.currentTimeMillis();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCollectionId() {
        return collectionId;
    }

    public void setCollectionId(String collectionId) {
        this.collectionId = collectionId != null ? collectionId : "";
    }

    public String getCollectionName() {
        return collectionName;
    }

    public void setCollectionName(String collectionName) {
        this.collectionName = collectionName != null ? collectionName : "";
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method != null ? method : "GET";
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path != null ? path : "/";
    }

    public String getFullUrl() {
        return fullUrl;
    }

    public void setFullUrl(String fullUrl) {
        this.fullUrl = fullUrl != null ? fullUrl : "";
    }

    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId != null ? profileId : "";
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName != null ? profileName : "[None]";
    }

    public int getAuthStatusCode() {
        return authStatusCode;
    }

    public void setAuthStatusCode(int authStatusCode) {
        this.authStatusCode = authStatusCode;
    }

    public int getAuthResponseLength() {
        return authResponseLength;
    }

    public void setAuthResponseLength(int authResponseLength) {
        this.authResponseLength = authResponseLength;
    }

    public long getAuthLatencyMs() {
        return authLatencyMs;
    }

    public void setAuthLatencyMs(long authLatencyMs) {
        this.authLatencyMs = authLatencyMs;
    }

    public int getUnauthStatusCode() {
        return unauthStatusCode;
    }

    public void setUnauthStatusCode(int unauthStatusCode) {
        this.unauthStatusCode = unauthStatusCode;
    }

    public int getUnauthResponseLength() {
        return unauthResponseLength;
    }

    public void setUnauthResponseLength(int unauthResponseLength) {
        this.unauthResponseLength = unauthResponseLength;
    }

    public long getUnauthLatencyMs() {
        return unauthLatencyMs;
    }

    public void setUnauthLatencyMs(long unauthLatencyMs) {
        this.unauthLatencyMs = unauthLatencyMs;
    }

    public AuthTestOutcome_littlespidy getOutcome() {
        return outcome != null ? outcome : AuthTestOutcome_littlespidy.SUCCESS;
    }

    public void setOutcome(AuthTestOutcome_littlespidy outcome) {
        this.outcome = outcome;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage != null ? errorMessage : "";
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getAuthRequestBytes() {
        return authRequestBytes;
    }

    public void setAuthRequestBytes(byte[] authRequestBytes) {
        this.authRequestBytes = authRequestBytes;
    }

    public byte[] getAuthResponseBytes() {
        return authResponseBytes;
    }

    public void setAuthResponseBytes(byte[] authResponseBytes) {
        this.authResponseBytes = authResponseBytes;
    }

    public byte[] getUnauthRequestBytes() {
        return unauthRequestBytes;
    }

    public void setUnauthRequestBytes(byte[] unauthRequestBytes) {
        this.unauthRequestBytes = unauthRequestBytes;
    }

    public byte[] getUnauthResponseBytes() {
        return unauthResponseBytes;
    }

    public void setUnauthResponseBytes(byte[] unauthResponseBytes) {
        this.unauthResponseBytes = unauthResponseBytes;
    }
}
