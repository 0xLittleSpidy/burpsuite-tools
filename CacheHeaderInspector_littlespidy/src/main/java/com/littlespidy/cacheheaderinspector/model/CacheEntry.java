// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;

/**
 * Immutable record capturing a single HTTP response's cache header values along with
 * the underlying request and response objects for previewing in Montoya editors.
 *
 * @author littlespidy
 */
public record CacheEntry(
    int id,
    String url,
    String host,
    String path,
    int statusCode,
    String contentType,
    String cacheControl,
    String pragma,
    String expires,
    String age,
    String etag,
    String lastModified,
    String vary,
    String xCache,
    String xCacheHits,
    String cdnCacheControl,
    String surrogateControl,
    String cfCacheStatus,
    HttpRequest request,
    HttpResponse response,
    ZonedDateTime timestamp
) {
    /**
     * Returns the value of the specified cache header for this entry.
     */
    public String getHeaderValue(String headerName) {
        return switch (headerName) {
            case "Cache-Control" -> cacheControl != null ? cacheControl : "";
            case "Pragma" -> pragma != null ? pragma : "";
            case "Expires" -> expires != null ? expires : "";
            case "Age" -> age != null ? age : "";
            case "ETag" -> etag != null ? etag : "";
            case "Last-Modified" -> lastModified != null ? lastModified : "";
            case "Vary" -> vary != null ? vary : "";
            case "X-Cache" -> xCache != null ? xCache : "";
            case "X-Cache-Hits" -> xCacheHits != null ? xCacheHits : "";
            case "CDN-Cache-Control" -> cdnCacheControl != null ? cdnCacheControl : "";
            case "Surrogate-Control" -> surrogateControl != null ? surrogateControl : "";
            case "CF-Cache-Status" -> cfCacheStatus != null ? cfCacheStatus : "";
            default -> "";
        };
    }
}
