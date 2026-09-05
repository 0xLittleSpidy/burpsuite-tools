// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a single detected sensitive finding in an HTTP response/request,
 * including precise character/byte offsets for auto-navigation and native Marker highlighting.
 */
public record FindingEntry(
        int id,
        FindingCategory category,
        String patternName,
        String matchValue,
        String matchLocation,
        String method,
        String url,
        String host,
        String path,
        short statusCode,
        String contentType,
        int contentLength,
        HttpRequestResponse requestResponse,
        String timeString,
        int startOffset,
        int endOffset
) {
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    public static FindingEntry create(
            int id,
            FindingCategory category,
            String patternName,
            String matchValue,
            String matchLocation,
            HttpRequestResponse requestResponse
    ) {
        return create(id, category, patternName, matchValue, matchLocation, requestResponse, -1, -1);
    }

    public static FindingEntry create(
            int id,
            FindingCategory category,
            String patternName,
            String matchValue,
            String matchLocation,
            HttpRequestResponse requestResponse,
            int startOffset,
            int endOffset
    ) {
        HttpRequest req = requestResponse.request();
        HttpResponse resp = requestResponse.response();

        String method = req != null ? req.method() : "UNKNOWN";
        String url = req != null ? req.url() : "";
        String host = (req != null && req.httpService() != null) ? req.httpService().host() : "";
        String path = req != null ? req.path() : "";

        short status = resp != null ? resp.statusCode() : 0;
        String contentType = "unknown";
        int length = 0;

        if (resp != null) {
            String ctHeader = resp.headerValue("Content-Type");
            if (ctHeader != null && !ctHeader.isBlank()) {
                contentType = ctHeader.split(";")[0].trim();
            }
            length = resp.body() != null ? resp.body().length() : 0;
        }

        String time = LocalTime.now().format(TIME_FORMATTER);

        return new FindingEntry(
                id,
                category,
                patternName,
                matchValue,
                matchLocation,
                method,
                url,
                host,
                path,
                status,
                contentType,
                length,
                requestResponse,
                time,
                startOffset,
                endOffset
        );
    }

    public boolean isResponseFinding() {
        return matchLocation == null || !matchLocation.toLowerCase().contains("request");
    }

    public boolean isHeaderFinding() {
        return matchLocation != null && matchLocation.toLowerCase().contains("header");
    }

    public boolean isBodyFinding() {
        return matchLocation == null || matchLocation.toLowerCase().contains("body");
    }

    public static String tsvHeader() {
        return "ID\tCategory\tPattern\tMatch Value\tLocation\tMethod\tURL\tHost\tStatus\tContent-Type\tLength\tTimestamp";
    }

    public String toTsvRow() {
        String cleanVal = matchValue != null ? matchValue.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') : "";
        String cleanUrl = url != null ? url.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') : "";
        String cleanHost = host != null ? host.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') : "";
        String cleanType = contentType != null ? contentType.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') : "";
        return String.format("%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s",
                id,
                category.getDisplayName(),
                patternName,
                cleanVal,
                matchLocation,
                method,
                cleanUrl,
                cleanHost,
                statusCode,
                cleanType,
                contentLength,
                timeString
        );
    }

    /**
     * Unique deduplication key per finding.
     */
    public String dedupeKey() {
        return method + "|" + url + "|" + category.name() + "|" + patternName + "|" + matchValue;
    }
}
