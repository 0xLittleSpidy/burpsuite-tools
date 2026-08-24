// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.PassiveMapStatus;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects Source Map indicators passively from HTTP response headers, trailing lines of JavaScript files,
 * or embedded inline base64 data URIs.
 *
 * @author littlespidy
 */
public class SourceMapDetector {

    private static final Pattern COMMENT_LINE_MAP_PATTERN = Pattern.compile(
        "//#\\s*sourceMappingURL=([^\r\n]+)|/\\*#\\s*sourceMappingURL=([^*]+)\\*/"
    );

    private static final Pattern INLINE_BASE64_PATTERN = Pattern.compile(
        "data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)"
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

        // 2. Scan JavaScript body (focus on last lines or entire body for minified single-line scripts)
        String body = response.bodyToString();
        if (body == null || body.trim().isEmpty()) {
            return new DetectionResult(PassiveMapStatus.NOT_FOUND, null);
        }

        // Look for inline base64 sourcemap first
        Matcher base64Matcher = INLINE_BASE64_PATTERN.matcher(body);
        if (base64Matcher.find()) {
            return new DetectionResult(PassiveMapStatus.INLINE_BASE64, base64Matcher.group(1));
        }

        // Look for trailing or embedded sourceMappingURL comment
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
                Matcher b64 = INLINE_BASE64_PATTERN.matcher(lastFoundMapUrl);
                if (b64.find()) {
                    return new DetectionResult(PassiveMapStatus.INLINE_BASE64, b64.group(1));
                }
            }
            String resolved = resolveUrl(scriptUrl, lastFoundMapUrl);
            return new DetectionResult(PassiveMapStatus.COMMENT_FOUND, resolved);
        }

        return new DetectionResult(PassiveMapStatus.NOT_FOUND, null);
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
