// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.PassiveMapStatus;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects Source Map indicators passively from HTTP response headers, trailing lines of JavaScript files,
 * or embedded inline data URIs (both base64 and percent-encoded, ported from js-recon).
 *
 * @author littlespidy
 */
public class SourceMapDetector {

    private static final Pattern COMMENT_LINE_MAP_PATTERN = Pattern.compile(
        "//#\\s*sourceMappingURL=([^\r\n]+)|/\\*#\\s*sourceMappingURL=([^*]+)\\*/"
    );

    private static final Pattern INLINE_DATA_URI_PATTERN = Pattern.compile(
        "data:application/json;[^,]*?,([A-Za-z0-9+/=%]+)"
    );

    public record DetectionResult(
        PassiveMapStatus status,
        String sourceMapLocation
    ) {}

    public static DetectionResult detect(String scriptUrl, HttpResponse response) {
        if (response == null) {
            return new DetectionResult(PassiveMapStatus.NOT_FOUND, null);
        }

        // 1. Check HTTP Response Headers
        String headerMap = response.headerValue("SourceMap");
        if (headerMap == null || headerMap.trim().isEmpty()) {
            headerMap = response.headerValue("X-SourceMap");
        }

        if (headerMap != null && !headerMap.trim().isEmpty()) {
            String resolved = resolveUrl(scriptUrl, headerMap.trim());
            return new DetectionResult(PassiveMapStatus.HEADER_FOUND, resolved);
        }

        // 2. Scan JavaScript body
        String body = response.bodyToString();
        return detect(scriptUrl, body);
    }

    public static DetectionResult detect(String scriptUrl, String body) {
        if (body == null || body.trim().isEmpty()) {
            return new DetectionResult(PassiveMapStatus.NOT_FOUND, null);
        }

        // Look for trailing or embedded sourceMappingURL comment first
        Matcher commentMatcher = COMMENT_LINE_MAP_PATTERN.matcher(body);
        String lastFoundMapUrl = null;
        while (commentMatcher.find()) {
            String url = commentMatcher.group(1) != null ? commentMatcher.group(1) : commentMatcher.group(2);
            if (url != null) {
                lastFoundMapUrl = url.trim();
            }
        }

        if (lastFoundMapUrl != null && !lastFoundMapUrl.isEmpty()) {
            if (lastFoundMapUrl.startsWith("data:")) {
                String decodedJson = decodeInlineSourceMapDataUri(lastFoundMapUrl);
                if (decodedJson != null) {
                    return new DetectionResult(PassiveMapStatus.INLINE_BASE64, decodedJson);
                }
            }
            String resolved = resolveUrl(scriptUrl, lastFoundMapUrl);
            return new DetectionResult(PassiveMapStatus.COMMENT_FOUND, resolved);
        }

        // Check for inline data URI directly in body
        Matcher dataUriMatcher = INLINE_DATA_URI_PATTERN.matcher(body);
        if (dataUriMatcher.find()) {
            String fullDataUri = dataUriMatcher.group(0);
            String decodedJson = decodeInlineSourceMapDataUri(fullDataUri);
            if (decodedJson != null) {
                return new DetectionResult(PassiveMapStatus.INLINE_BASE64, decodedJson);
            }
        }

        return new DetectionResult(PassiveMapStatus.NOT_FOUND, null);
    }

    /**
     * Decodes an inline `data:` URI sourceMappingURL reference into raw source-map JSON text.
     * Handles both base64 and percent-encoded payloads, validating the "sources" JSON array.
     */
    public static String decodeInlineSourceMapDataUri(String rawRef) {
        if (rawRef == null || !rawRef.startsWith("data:")) return null;

        int commaIndex = rawRef.indexOf(',');
        if (commaIndex == -1) return null;

        String meta = rawRef.substring(5, commaIndex);
        String payload = rawRef.substring(commaIndex + 1).trim();
        boolean isBase64 = meta.contains("base64");

        try {
            String decoded;
            if (isBase64) {
                byte[] bytes = Base64.getDecoder().decode(payload);
                decoded = new String(bytes, StandardCharsets.UTF_8);
            } else {
                decoded = URLDecoder.decode(payload, StandardCharsets.UTF_8);
            }

            if (decoded.contains("\"sources\"") && (decoded.startsWith("{") || decoded.startsWith("["))) {
                return decoded;
            }
            return decoded;
        } catch (Exception ex) {
            return null;
        }
    }

    public static String resolveUrl(String baseScriptUrl, String mapRelativeUrl) {
        if (mapRelativeUrl == null || mapRelativeUrl.isEmpty()) return "";
        if (mapRelativeUrl.startsWith("http://") || mapRelativeUrl.startsWith("https://")) {
            return mapRelativeUrl;
        }

        try {
            URI baseUri = new URI(baseScriptUrl);
            URI resolvedUri = baseUri.resolve(mapRelativeUrl);
            return resolvedUri.toString();
        } catch (Exception ex) {
            if (baseScriptUrl.endsWith("/")) {
                return baseScriptUrl + mapRelativeUrl;
            }
            int lastSlash = baseScriptUrl.lastIndexOf('/');
            if (lastSlash != -1) {
                return baseScriptUrl.substring(0, lastSlash + 1) + mapRelativeUrl;
            }
            return baseScriptUrl + "/" + mapRelativeUrl;
        }
    }
}
