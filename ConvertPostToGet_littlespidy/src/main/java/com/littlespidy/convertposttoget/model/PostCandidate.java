// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Immutable representation of a discovered POST endpoint candidate.
 * Includes parameterTypes to facilitate granular triage filtering.
 *
 * @author littlespidy
 */
public record PostCandidate(
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
    Set<String> parameterTypes,
    boolean isAuthenticated,
    String authIndicator,
    String dedupeKey,
    HttpRequest request,
    HttpResponse response,
    ZonedDateTime time
) {}
