package com.littlespidy.uploadscanner.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.uploadscanner.model.ReDownloaderConfig;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Core engine for ReDownloader URL parsing, marker offset calculation,
 * and redownload request generation/execution.
 *
 * @author littlespidy
 */
public class ReDownloaderEngine {
    private final MontoyaApi api;
    private final ReDownloaderConfig config;
    private final Random random = new Random();

    public ReDownloaderEngine(MontoyaApi api, ReDownloaderConfig config) {
        this.api = api;
        this.config = config;
    }

    /**
     * Resolves placeholders (${FILENAME}, ${FILENAME_NO_EXT}, ${ORIG_EXT}, ${RANDOMIZE}) in a pattern.
     */
    public String resolvePlaceholders(String pattern, String filename) {
        if (pattern == null || pattern.isEmpty()) {
            return "";
        }
        if (filename == null) {
            filename = "test.jpg";
        }

        String nameWithoutExt = filename;
        String ext = "";
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex > 0) {
            nameWithoutExt = filename.substring(0, dotIndex);
            ext = filename.substring(dotIndex + 1);
        }

        String encodedFilename = URLEncoder.encode(filename, StandardCharsets.UTF_8).replace("+", "%20");
        String encodedNameWithoutExt = URLEncoder.encode(nameWithoutExt, StandardCharsets.UTF_8).replace("+", "%20");

        String result = pattern
                .replace(ReDownloaderConfig.MARKER_FILENAME, filename)
                .replace("${ENCODED_FILENAME}", encodedFilename)
                .replace(ReDownloaderConfig.MARKER_FILENAME_NO_EXT, nameWithoutExt)
                .replace("${ENCODED_FILENAME_NO_EXT}", encodedNameWithoutExt)
                .replace(ReDownloaderConfig.MARKER_ORIG_EXT, ext);

        if (result.contains(ReDownloaderConfig.MARKER_RANDOMIZE)) {
            long randNum = 100000000000L + (long) (random.nextDouble() * 899999999999L);
            result = result.replace(ReDownloaderConfig.MARKER_RANDOMIZE, String.valueOf(randNum));
        }

        return result;
    }

    /**
     * Parses the download URL from the response using start/end markers or static URL.
     */
    public MarkerHighlighter.ExtractionResult parseDownloadUrl(String responseContent, String sentFilename) {
        if (!config.isEnabled()) {
            return MarkerHighlighter.ExtractionResult.notFound();
        }

        // 1. Start / End Marker parsing
        if (!config.getStartMarker().isEmpty() && !config.getEndMarker().isEmpty()) {
            if (responseContent == null || responseContent.isEmpty()) {
                return MarkerHighlighter.ExtractionResult.notFound();
            }

            String startMarker = resolvePlaceholders(config.getStartMarker(), sentFilename);
            String endMarker = resolvePlaceholders(config.getEndMarker(), sentFilename);

            MarkerHighlighter.ExtractionResult extraction =
                    MarkerHighlighter.extractBetweenMarkers(responseContent, startMarker, endMarker);

            if (extraction.isFound()) {
                String rawUrl = extraction.getExtractedText();
                if (config.isReplaceBackslash()) {
                    rawUrl = rawUrl.replace("\\/", "/");
                }

                String prefix = resolvePlaceholders(config.getUrlPrefix(), sentFilename);
                String suffix = resolvePlaceholders(config.getUrlSuffix(), sentFilename);
                String finalUrl = prefix + rawUrl + suffix;

                return new MarkerHighlighter.ExtractionResult(
                        true,
                        finalUrl,
                        extraction.getStartMarkerOffset(),
                        extraction.getEndMarkerOffset(),
                        extraction.getContentStartOffset(),
                        extraction.getContentEndOffset()
                );
            }
        }

        // 2. Static URL alternative
        if (!config.getStaticUrl().isEmpty()) {
            String staticUrl = resolvePlaceholders(config.getStaticUrl(), sentFilename);
            return new MarkerHighlighter.ExtractionResult(true, staticUrl, 0, 0, 0, staticUrl.length());
        }

        return MarkerHighlighter.ExtractionResult.notFound();
    }

    /**
     * Constructs a GET redownload request targeting the parsed URL,
     * preserving Cookie and Authorization headers from the original upload request.
     */
    public HttpRequest buildRedownloadRequest(HttpRequest baseRequest, String parsedUrl) {
        if (parsedUrl == null || parsedUrl.isEmpty()) {
            return null;
        }

        HttpRequest req;
        if (parsedUrl.startsWith("http://") || parsedUrl.startsWith("https://")) {
            req = HttpRequest.httpRequestFromUrl(parsedUrl);
        } else {
            HttpService service = (baseRequest != null && baseRequest.httpService() != null) ? baseRequest.httpService() : null;
            String normalizedPath = parsedUrl.startsWith("/") ? parsedUrl : "/" + parsedUrl;

            String userAgent = (baseRequest != null && baseRequest.hasHeader("User-Agent"))
                    ? baseRequest.headerValue("User-Agent")
                    : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

            if (service != null) {
                req = HttpRequest.httpRequest(service, "GET " + normalizedPath + " HTTP/1.1\r\n" +
                        "Host: " + service.host() + "\r\n" +
                        "User-Agent: " + userAgent + "\r\n" +
                        "Accept: */*\r\n" +
                        "Connection: close\r\n\r\n");
            } else {
                req = HttpRequest.httpRequest("GET " + normalizedPath + " HTTP/1.1\r\n" +
                        "User-Agent: " + userAgent + "\r\n" +
                        "Accept: */*\r\n" +
                        "Connection: close\r\n\r\n");
            }
        }

        // Attach Cookie, Authorization, and authentication/token headers present in upload request
        if (baseRequest != null && baseRequest.headers() != null) {
            for (HttpHeader header : baseRequest.headers()) {
                if (isCookieOrAuthHeader(header.name())) {
                    if (header.name().equalsIgnoreCase("cookie") && req.hasHeader("cookie")) {
                        String existing = req.headerValue("cookie");
                        if (!existing.contains(header.value())) {
                            req = req.withUpdatedHeader("Cookie", existing + "; " + header.value());
                        }
                    } else if (req.hasHeader(header.name())) {
                        req = req.withUpdatedHeader(header.name(), header.value());
                    } else {
                        req = req.withAddedHeader(header.name(), header.value());
                    }
                }
            }
        }

        return req;
    }

    /**
     * Determines whether a header name corresponds to a cookie, authorization, or token header.
     */
    public static boolean isCookieOrAuthHeader(String name) {
        if (name == null || name.trim().isEmpty()) {
            return false;
        }
        String lower = name.toLowerCase().trim();
        return lower.equals("cookie") ||
                lower.equals("authorization") ||
                lower.equals("proxy-authorization") ||
                lower.startsWith("x-auth") ||
                lower.startsWith("auth") ||
                lower.contains("token") ||
                lower.contains("api-key") ||
                lower.contains("apikey") ||
                lower.contains("jwt") ||
                lower.contains("bearer") ||
                lower.contains("session");
    }

    /**
     * Executes the redownload HTTP request and wraps it with markers.
     */
    public HttpRequestResponse executeRedownload(HttpRequest redownloadRequest, String searchPayload) {
        if (redownloadRequest == null) {
            return null;
        }

        HttpRequestResponse responsePair = api.http().sendRequest(redownloadRequest);
        if (responsePair != null && responsePair.hasResponse() && searchPayload != null && !searchPayload.isEmpty()) {
            HttpResponse resp = responsePair.response();
            List<Marker> respMarkers = MarkerHighlighter.findMarkers(resp.bodyToString(), searchPayload);
            if (!respMarkers.isEmpty()) {
                responsePair = responsePair.withResponseMarkers(respMarkers);
            }
        }
        return responsePair;
    }

    /**
     * Executes optional preflight request if configured.
     */
    public HttpRequestResponse executePreflight(HttpRequest baseRequest) {
        if (!config.isEnabled() || config.getPreflightUrl().isEmpty()) {
            return null;
        }

        String preflightUrl = resolvePlaceholders(config.getPreflightUrl(), null);
        HttpRequest preflightReq;
        if (preflightUrl.startsWith("http://") || preflightUrl.startsWith("https://")) {
            preflightReq = HttpRequest.httpRequestFromUrl(preflightUrl);
        } else {
            HttpService service = baseRequest.httpService();
            String path = preflightUrl.startsWith("/") ? preflightUrl : "/" + preflightUrl;
            preflightReq = HttpRequest.httpRequest(service, "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + service.host() + "\r\n" +
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
                    "Accept: */*\r\n" +
                    "Connection: close\r\n\r\n");
        }

        return api.http().sendRequest(preflightReq);
    }

    /**
     * Holds the result of an automated or selection-driven URL detection.
     */
    public static class DetectionResult {
        private final boolean found;
        private final String detectedUrl;
        private final String suggestedStartMarker;
        private final String suggestedEndMarker;
        private final String reason;

        public DetectionResult(boolean found, String detectedUrl, String suggestedStartMarker, String suggestedEndMarker, String reason) {
            this.found = found;
            this.detectedUrl = detectedUrl != null ? detectedUrl : "";
            this.suggestedStartMarker = suggestedStartMarker != null ? suggestedStartMarker : "";
            this.suggestedEndMarker = suggestedEndMarker != null ? suggestedEndMarker : "";
            this.reason = reason != null ? reason : "";
        }

        public static DetectionResult found(String url, String startMarker, String endMarker, String reason) {
            return new DetectionResult(true, url, startMarker, endMarker, reason);
        }

        public static DetectionResult notFound(String reason) {
            return new DetectionResult(false, "", "", "", reason);
        }

        public boolean isFound() { return found; }
        public String getDetectedUrl() { return detectedUrl; }
        public String getSuggestedStartMarker() { return suggestedStartMarker; }
        public String getSuggestedEndMarker() { return suggestedEndMarker; }
        public String getReason() { return reason; }
    }

    /**
     * Automatically scans response headers, JSON keys, HTML attributes, and filename reflections
     * to discover the download URL with zero manual configuration.
     */
    public DetectionResult autoDetectDownloadUrl(HttpResponse response, String uploadedFilename) {
        if (response == null) {
            return DetectionResult.notFound("No response provided to analyze.");
        }

        java.util.List<String> headerLines = new java.util.ArrayList<>();
        try {
            if (response.headers() != null) {
                for (burp.api.montoya.http.message.HttpHeader header : response.headers()) {
                    headerLines.add(header.name() + ": " + header.value());
                }
            }
        } catch (Exception ignored) {}

        String body = "";
        try {
            body = response.bodyToString();
        } catch (Exception ignored) {}

        return autoDetectDownloadUrl(headerLines, body, uploadedFilename);
    }

    /**
     * Overload for raw HTTP response string (useful for offline analysis, tests, and raw editor parsing).
     */
    public DetectionResult autoDetectDownloadUrl(String rawResponse, String uploadedFilename) {
        if (rawResponse == null || rawResponse.trim().isEmpty()) {
            return DetectionResult.notFound("No response provided to analyze.");
        }

        java.util.List<String> headerLines = new java.util.ArrayList<>();
        String body = "";

        int headerEnd = rawResponse.indexOf("\r\n\r\n");
        int sepLen = 4;
        if (headerEnd == -1) {
            headerEnd = rawResponse.indexOf("\n\n");
            sepLen = 2;
        }

        if (headerEnd != -1) {
            String headPart = rawResponse.substring(0, headerEnd);
            body = rawResponse.substring(headerEnd + sepLen);
            String[] lines = headPart.split("\r?\n");
            for (String line : lines) {
                headerLines.add(line);
            }
        } else {
            body = rawResponse;
        }

        return autoDetectDownloadUrl(headerLines, body, uploadedFilename);
    }

    /**
     * Core detection logic scanning header lines, body patterns, filename reflections, and JSON/HTML structures.
     */
    public DetectionResult autoDetectDownloadUrl(java.util.List<String> headers, String body, String uploadedFilename) {
        // 1. Check HTTP Redirect / Location Header
        if (headers != null) {
            for (String header : headers) {
                int colonIdx = header.indexOf(':');
                if (colonIdx > 0) {
                    String name = header.substring(0, colonIdx).trim();
                    String val = header.substring(colonIdx + 1).trim();
                    if (name.equalsIgnoreCase("Location") || name.equalsIgnoreCase("Content-Location")) {
                        if (!val.isEmpty()) {
                            return DetectionResult.found(val, "", "", "Detected from '" + name + "' HTTP header");
                        }
                    }
                }
            }
        }

        if (body == null || body.trim().isEmpty()) {
            return DetectionResult.notFound("Response body is empty.");
        }

        // 2. Search for uploadedFilename in the body (filename reflection)
        if (uploadedFilename != null && !uploadedFilename.trim().isEmpty() && body.contains(uploadedFilename)) {
            int fileIdx = body.indexOf(uploadedFilename);
            int openQuoteIdx = -1;
            char delimiter = '"';
            for (int i = fileIdx - 1; i >= Math.max(0, fileIdx - 250); i--) {
                char c = body.charAt(i);
                if (c == '"' || c == '\'' || c == '>' || c == '`') {
                    openQuoteIdx = i;
                    delimiter = c;
                    break;
                }
            }

            int closeQuoteIdx = -1;
            char expectedClose = delimiter == '>' ? '<' : delimiter;
            for (int i = fileIdx + uploadedFilename.length(); i < Math.min(body.length(), fileIdx + uploadedFilename.length() + 250); i++) {
                char c = body.charAt(i);
                if (c == expectedClose) {
                    closeQuoteIdx = i;
                    break;
                }
            }

            if (openQuoteIdx != -1 && closeQuoteIdx != -1 && closeQuoteIdx > openQuoteIdx) {
                String fullPath = body.substring(openQuoteIdx + 1, closeQuoteIdx).trim();
                if (fullPath.contains("/") || fullPath.contains("\\/")) {
                    int markerStart = Math.max(0, openQuoteIdx - 20);
                    int colonIdx = body.lastIndexOf(':', openQuoteIdx);
                    int eqIdx = body.lastIndexOf('=', openQuoteIdx);
                    if (colonIdx > markerStart) markerStart = Math.max(0, colonIdx - 10);
                    if (eqIdx > markerStart) markerStart = Math.max(0, eqIdx - 6);

                    String startMarker = body.substring(markerStart, openQuoteIdx + 1);
                    String endMarker = String.valueOf(expectedClose);

                    if (config.isReplaceBackslash()) {
                        fullPath = fullPath.replace("\\/", "/");
                    }
                    return DetectionResult.found(fullPath, startMarker, endMarker, "Detected from filename '" + uploadedFilename + "' reflection in response");
                }
            }
        }

        // 3. Scan JSON keys for URL / Path
        java.util.regex.Pattern jsonPattern = java.util.regex.Pattern.compile(
                "\"([a-zA-Z0-9_-]*(?:url|path|file|location|download|src|href|avatar|image|link)[a-zA-Z0-9_-]*)\"\\s*:\\s*\"([^\"]+)\"",
                java.util.regex.Pattern.CASE_INSENSITIVE
        );
        java.util.regex.Matcher jsonMatcher = jsonPattern.matcher(body);
        if (jsonMatcher.find()) {
            String key = jsonMatcher.group(1);
            String rawVal = jsonMatcher.group(2);
            if (rawVal.contains("/") || rawVal.contains("\\/") || rawVal.contains(".")) {
                String matchedToken = jsonMatcher.group(0);
                int valOffset = matchedToken.indexOf(rawVal);
                String startMarker = valOffset > 0 ? matchedToken.substring(0, valOffset) : "\"" + key + "\":\"";
                String endMarker = "\"";
                String cleanUrl = config.isReplaceBackslash() ? rawVal.replace("\\/", "/") : rawVal;
                return DetectionResult.found(cleanUrl, startMarker, endMarker, "Auto-detected from JSON key '" + key + "'");
            }
        }

        // 4. Scan HTML attributes (<a href>, <img src>, <source src>)
        java.util.regex.Pattern htmlPattern = java.util.regex.Pattern.compile(
                "<(?:a|img|source|iframe|embed)\\b[^>]*\\b(?:href|src)=[\"']([^\"']+\\.(?:png|jpe?g|gif|webp|svg|pdf|docx?|xlsx?|txt|php[0-9]?|phtml|jspx?|aspx?|cgi|sh))[\"']",
                java.util.regex.Pattern.CASE_INSENSITIVE
        );
        java.util.regex.Matcher htmlMatcher = htmlPattern.matcher(body);
        if (htmlMatcher.find()) {
            String rawUrl = htmlMatcher.group(1);
            int urlStart = body.indexOf(rawUrl);
            int attrStart = Math.max(0, urlStart - 10);
            int hrefIdx = body.lastIndexOf("href=", urlStart);
            int srcIdx = body.lastIndexOf("src=", urlStart);
            if (hrefIdx != -1 && hrefIdx >= urlStart - 20) {
                attrStart = hrefIdx;
            } else if (srcIdx != -1 && srcIdx >= urlStart - 20) {
                attrStart = srcIdx;
            }
            String startMarker = body.substring(attrStart, urlStart);
            char quoteChar = body.charAt(urlStart + rawUrl.length());
            String endMarker = String.valueOf(quoteChar);
            return DetectionResult.found(rawUrl, startMarker, endMarker, "Auto-detected from HTML media / link tag");
        }

        return DetectionResult.notFound("No file URL or path pattern recognized automatically.");
    }

    /**
     * Derives unique start and end markers from user text selection in response viewer.
     */
    public DetectionResult deriveMarkersFromSelection(String fullText, int selStart, int selEnd) {
        if (fullText == null || fullText.isEmpty() || selStart < 0 || selEnd > fullText.length() || selStart >= selEnd) {
            return DetectionResult.notFound("Invalid selection range.");
        }

        String selectedText = fullText.substring(selStart, selEnd);
        if (selectedText.trim().isEmpty()) {
            return DetectionResult.notFound("Selected text is empty.");
        }

        // Scan backwards for starting boundary delimiter
        int preStart = Math.max(0, selStart - 1);
        for (int i = selStart - 1; i >= Math.max(0, selStart - 30); i--) {
            char c = fullText.charAt(i);
            if (c == '"' || c == '\'' || c == '>' || c == '=' || c == ':' || c == '\n') {
                preStart = i;
                break;
            }
        }
        int keyStart = Math.max(0, preStart - 15);
        for (int i = preStart - 1; i >= Math.max(0, preStart - 25); i--) {
            char c = fullText.charAt(i);
            if (c == '"' || c == '<' || c == ' ' || c == '\n') {
                keyStart = i;
                break;
            }
        }

        String startMarker = fullText.substring(keyStart, selStart);
        if (startMarker.isEmpty()) {
            startMarker = fullText.substring(Math.max(0, selStart - 5), selStart);
        }

        // Scan forwards for ending boundary delimiter
        int postEnd = Math.min(fullText.length(), selEnd + 1);
        for (int i = selEnd; i < Math.min(fullText.length(), selEnd + 15); i++) {
            char c = fullText.charAt(i);
            if (c == '"' || c == '\'' || c == '<' || c == ' ' || c == '&' || c == '\r' || c == '\n' || c == ',' || c == '}') {
                postEnd = i + 1;
                break;
            }
        }

        String endMarker = fullText.substring(selEnd, postEnd);
        if (endMarker.isEmpty()) {
            endMarker = fullText.substring(selEnd, Math.min(fullText.length(), selEnd + 1));
        }

        return DetectionResult.found(selectedText, startMarker, endMarker, "Derived markers from highlighted text");
    }
}
