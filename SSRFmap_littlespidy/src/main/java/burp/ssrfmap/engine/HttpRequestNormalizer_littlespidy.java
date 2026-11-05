// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.engine;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpRequestNormalizer_littlespidy {

    private static final Pattern CONTENT_LENGTH_PATTERN = Pattern.compile("(?i)^Content-Length:\\s*\\d+$");

    public static String normalizeRequestText(String rawRequestText) {
        if (rawRequestText == null) {
            return "";
        }

        // 1. Normalize line endings to \n first, then split header and body
        String unified = rawRequestText.replace("\r\n", "\n").replace("\r", "\n");

        String headerPart;
        String bodyPart;
        int doubleNewline = unified.indexOf("\n\n");
        if (doubleNewline != -1) {
            headerPart = unified.substring(0, doubleNewline);
            bodyPart = unified.substring(doubleNewline + 2);
        } else {
            headerPart = unified;
            bodyPart = "";
        }

        byte[] bodyBytes = bodyPart.getBytes(StandardCharsets.UTF_8);

        // 2. Process headers line-by-line, updating Content-Length if present
        String[] headerLines = headerPart.split("\n");
        StringBuilder normalizedHeaders = new StringBuilder();
        boolean hasContentLength = false;

        for (int i = 0; i < headerLines.length; i++) {
            String line = headerLines[i].trim();
            if (line.isEmpty() && i > 0) {
                continue;
            }

            Matcher clMatcher = CONTENT_LENGTH_PATTERN.matcher(line);
            if (clMatcher.matches()) {
                hasContentLength = true;
                normalizedHeaders.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
            } else {
                normalizedHeaders.append(line).append("\r\n");
            }
        }

        // If POST/PUT/PATCH and body is present but no Content-Length header was found, append it
        String requestLine = headerLines.length > 0 ? headerLines[0].trim().toUpperCase() : "";
        if (!hasContentLength && !bodyPart.isEmpty() && (requestLine.startsWith("POST ") || requestLine.startsWith("PUT ") || requestLine.startsWith("PATCH "))) {
            normalizedHeaders.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        }

        // 3. Recombine headers and body with proper CRLF
        normalizedHeaders.append("\r\n");
        normalizedHeaders.append(bodyPart);

        return normalizedHeaders.toString();
    }

    public static byte[] normalizeRequestBytes(String rawRequestText) {
        String normalized = normalizeRequestText(rawRequestText);
        return normalized.getBytes(StandardCharsets.UTF_8);
    }

    public static HttpRequest createNormalizedRequest(HttpService httpService, String rawRequestText) {
        byte[] fullRequestBytes = normalizeRequestBytes(rawRequestText);
        return HttpRequest.httpRequest(httpService, ByteArray.byteArray(fullRequestBytes));
    }
}
