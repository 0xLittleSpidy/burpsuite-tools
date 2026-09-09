// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents an item in the Token Attacker queue, storing the original HTTP request/response
 * and execution results across all tested JWT tokens and unauthenticated baseline probes.
 */
public class AttackedRequestEntry {

    private final int id;
    private final HttpRequest originalRequest;
    private final HttpResponse originalResponse;
    private final String method;
    private final String url;
    private final String path;
    private final int originalStatusCode;
    private final int originalLength;

    private final Map<Integer, TokenAttackResult> tokenResults = new ConcurrentHashMap<>();
    private volatile TokenAttackResult unauthenticatedResult;
    private volatile String assessment = "Queued";
    private volatile String status = "Queued";

    public AttackedRequestEntry(int id, HttpRequest request, HttpResponse response) {
        this.id = id;
        this.originalRequest = request;
        this.originalResponse = response;

        this.method = request != null ? request.method() : "GET";
        this.url = request != null ? request.url() : "";
        this.path = request != null ? request.path() : "";
        this.originalStatusCode = response != null ? response.statusCode() : 0;
        this.originalLength = (response != null && response.body() != null) ? response.body().length() : 0;
    }

    public static AttackedRequestEntry from(int id, HttpRequestResponse rr) {
        if (rr == null) {
            return new AttackedRequestEntry(id, null, null);
        }
        return new AttackedRequestEntry(id, rr.request(), rr.hasResponse() ? rr.response() : null);
    }

    public int getId() {
        return id;
    }

    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    public HttpResponse getOriginalResponse() {
        return originalResponse;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public String getPath() {
        return path;
    }

    public int getOriginalStatusCode() {
        return originalStatusCode;
    }

    public int getOriginalLength() {
        return originalLength;
    }

    public void addTokenResult(int slotIndex, TokenAttackResult result) {
        tokenResults.put(slotIndex, result);
    }

    public TokenAttackResult getTokenResult(int slotIndex) {
        return tokenResults.get(slotIndex);
    }

    public Map<Integer, TokenAttackResult> getTokenResults() {
        return Collections.unmodifiableMap(tokenResults);
    }

    public TokenAttackResult getUnauthenticatedResult() {
        return unauthenticatedResult;
    }

    public void setUnauthenticatedResult(TokenAttackResult unauthenticatedResult) {
        this.unauthenticatedResult = unauthenticatedResult;
    }

    public String getAssessment() {
        return assessment;
    }

    public void setAssessment(String assessment) {
        this.assessment = assessment != null ? assessment : "";
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status != null ? status : "";
    }

    public void clearResults() {
        tokenResults.clear();
        unauthenticatedResult = null;
        assessment = "Queued";
        status = "Queued";
    }
}
