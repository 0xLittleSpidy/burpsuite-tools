// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.Objects;

/**
 * Utility methods for response filtering, MIME validation, size guards, and decoding.
 * Ported and adapted from sensitive-discoverer.
 */
public final class ScannerUtils {

    /**
     * Maximum response size in bytes (10 MB) to protect against memory exhaustion.
     */
    public static final int MAX_RESPONSE_SIZE = 10 * 1024 * 1024;

    /**
     * Set of binary and media MIME types that should be skipped to avoid unnecessary
     * CPU consumption and false positive pattern matching.
     */
    public static final EnumSet<MimeType> BLACKLISTED_MIME_TYPES = EnumSet.of(
            MimeType.APPLICATION_FLASH,
            MimeType.FONT_WOFF,
            MimeType.FONT_WOFF2,
            MimeType.IMAGE_BMP,
            MimeType.IMAGE_GIF,
            MimeType.IMAGE_JPEG,
            MimeType.IMAGE_PNG,
            MimeType.IMAGE_SVG_XML,
            MimeType.IMAGE_TIFF,
            MimeType.IMAGE_UNKNOWN,
            MimeType.LEGACY_SER_AMF,
            MimeType.RTF,
            MimeType.SOUND,
            MimeType.VIDEO,
            MimeType.SCRIPT
    );

    private ScannerUtils() {}

    /**
     * Checks if the response body exceeds the maximum scanning threshold.
     */
    public static boolean isOversized(HttpResponse response) {
        return response != null && response.body() != null && response.body().length() > MAX_RESPONSE_SIZE;
    }

    /**
     * Checks if the response or its body is null or empty.
     */
    public static boolean isResponseEmpty(HttpResponse response) {
        return response == null || (response.body() == null && (response.headers() == null || response.headers().isEmpty()));
    }

    /**
     * Checks if the response declared or inferred MIME type is blacklisted (e.g. image, video, font).
     */
    public static boolean isMimeTypeBlacklisted(HttpResponse response) {
        if (response == null) return false;
        MimeType stated = response.statedMimeType();
        if (stated != null && stated != MimeType.NONE && BLACKLISTED_MIME_TYPES.contains(stated)) {
            return true;
        }
        MimeType inferred = response.inferredMimeType();
        if ((stated == null || stated == MimeType.NONE) && inferred != null && BLACKLISTED_MIME_TYPES.contains(inferred)) {
            return true;
        }
        return false;
    }

    /**
     * Checks if a URL path or filename corresponds to JavaScript source or source map.
     */
    public static boolean isJsPath(String path) {
        if (path == null || path.isEmpty()) return false;
        int qIdx = path.indexOf('?');
        String clean = qIdx != -1 ? path.substring(0, qIdx) : path;
        int hIdx = clean.indexOf('#');
        if (hIdx != -1) clean = clean.substring(0, hIdx);
        String lower = clean.toLowerCase();
        return lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")
                || lower.endsWith(".jsx") || lower.endsWith(".ts") || lower.endsWith(".tsx")
                || lower.endsWith(".map") || lower.endsWith(".js.map");
    }

    /**
     * Checks if a Content-Type header string indicates JavaScript MIME types.
     */
    public static boolean isJsContentType(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase();
        return lower.contains("javascript") || lower.contains("ecmascript") || lower.contains("/x-javascript");
    }

    /**
     * Identifies JavaScript files, scripts, and source maps that must be skipped in Response Inspector,
     * as dedicated JavaScript analysis is handled by the JS SourceMap Explorer extension.
     */
    public static boolean isJsFile(HttpRequest request, HttpResponse response) {
        if (request != null) {
            String path = request.path();
            if (path == null || path.isEmpty()) {
                path = request.url();
            }
            if (isJsPath(path)) {
                return true;
            }
        }
        if (response != null) {
            MimeType stated = response.statedMimeType();
            if (stated == MimeType.SCRIPT) return true;
            MimeType inferred = response.inferredMimeType();
            if (inferred == MimeType.SCRIPT) return true;

            String contentType = response.headerValue("Content-Type");
            if (isJsContentType(contentType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Decodes a ByteArray to a String using UTF-8 without expensive reflection.
     */
    public static String convertByteArrayToString(ByteArray byteArray) {
        if (byteArray == null || byteArray.length() == 0) {
            return "";
        }
        return new String(byteArray.getBytes(), StandardCharsets.UTF_8);
    }

    /**
     * Extracts the raw response header block as a String with precise 0-indexed byte alignment.
     */
    public static String extractHeadersString(HttpResponse response) {
        if (response == null) return "";
        int bodyOffset = response.bodyOffset();
        if (bodyOffset > 0 && response.toByteArray().length() >= bodyOffset) {
            return new String(response.toByteArray().subArray(0, bodyOffset).getBytes(), StandardCharsets.UTF_8);
        }
        if (response.headers() != null && !response.headers().isEmpty()) {
            return String.join("\r\n", response.headers().stream().map(Objects::toString).toList());
        }
        return "";
    }
}
