package com.littlespidy.inputvalidationfuzzer.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Captures the outcome of a single fuzz execution against an insertion point.
 *
 * @author littlespidy
 */
public record FuzzResult(
    int id,
    String parameterName,
    String parameterType,
    String payloadName,
    String payloadValue,
    int baseStatus,
    int baseLength,
    int responseStatus,
    int responseLength,
    String responseContentType,
    String signal,
    String issueSeverity,
    String evidence,
    HttpRequest request,
    HttpResponse response,
    HttpRequest baseRequest,
    HttpResponse baseResponse,
    HttpRequestResponse requestResponse,
    ZonedDateTime timestamp
) {
    public boolean hasResponse() {
        return response != null;
    }
}
