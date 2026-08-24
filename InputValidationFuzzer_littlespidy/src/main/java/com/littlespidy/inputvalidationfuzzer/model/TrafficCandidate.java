package com.littlespidy.inputvalidationfuzzer.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable representation of a discovered traffic candidate from Proxy history.
 *
 * @author littlespidy
 */
public record TrafficCandidate(
    int id,
    String method,
    String url,
    String host,
    String path,
    int statusCode,
    int contentLength,
    String contentType,
    int parameterCount,
    List<String> parameterNames,
    boolean isAuthenticated,
    String authIndicator,
    String dedupeKey,
    HttpRequest request,
    HttpResponse response,
    ZonedDateTime time
) {}
