package com.littlespidy.convertposttoget.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Captures the outcome of converting a POST request to GET and testing the server response.
 *
 * @author littlespidy
 */
public record ConversionResult(
    int id,
    String method,
    String url,
    String host,
    String path,
    int baseStatus,
    int baseLength,
    int getStatus,
    int getLength,
    String getContentType,
    String signal,
    String severity,
    String evidence,
    HttpRequest originalPostRequest,
    HttpResponse originalPostResponse,
    HttpRequest convertedGetRequest,
    HttpResponse convertedGetResponse,
    HttpRequestResponse convertedRequestResponse,
    ZonedDateTime timestamp
) {}
