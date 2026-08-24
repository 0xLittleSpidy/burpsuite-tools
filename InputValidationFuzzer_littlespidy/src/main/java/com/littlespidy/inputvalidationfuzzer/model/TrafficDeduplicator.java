package com.littlespidy.inputvalidationfuzzer.model;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Deduplication helper that normalizes endpoint paths and parameter signatures.
 *
 * @author littlespidy
 */
public class TrafficDeduplicator {
    private static final Pattern NUMERIC_SEGMENT = Pattern.compile("/\\d+(?=/|$)");
    private static final Pattern UUID_SEGMENT = Pattern.compile("/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)");
    private static final Pattern HEX_SEGMENT = Pattern.compile("/[0-9a-fA-F]{16,64}(?=/|$)");

    public static String computeDedupeKey(HttpRequest request, boolean includeCookies) {
        String method = request.method();
        String host = request.httpService() != null ? request.httpService().host() : "";
        int port = request.httpService() != null ? request.httpService().port() : 80;
        String path = request.path() != null ? request.path() : "/";

        int queryIdx = path.indexOf('?');
        if (queryIdx != -1) {
            path = path.substring(0, queryIdx);
        }

        String normalizedPath = NUMERIC_SEGMENT.matcher(path).replaceAll("/{id}");
        normalizedPath = UUID_SEGMENT.matcher(normalizedPath).replaceAll("/{uuid}");
        normalizedPath = HEX_SEGMENT.matcher(normalizedPath).replaceAll("/{hash}");

        List<ParsedHttpParameter> params = request.parameters();
        String paramNames = params.stream()
            .filter(p -> includeCookies || p.type() != HttpParameterType.COOKIE)
            .map(p -> p.type().name() + ":" + p.name())
            .sorted()
            .collect(Collectors.joining("&"));

        String contentType = request.headerValue("Content-Type");
        if (contentType == null) contentType = "";

        return method + "|" + host + ":" + port + "|" + normalizedPath + "|" + paramNames + "|" + contentType;
    }
}
