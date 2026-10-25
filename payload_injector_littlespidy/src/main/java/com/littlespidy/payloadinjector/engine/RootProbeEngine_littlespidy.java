// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.engine;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Engine responsible for generating web root probes:
 * 1. Testing HTTP PUT file upload capability targeting the web root.
 * 2. Probing important files and directories (such as robots.txt).
 *
 * @author littlespidy
 */
public class RootProbeEngine_littlespidy {

    public static final String DEFAULT_PUT_FILENAME = "/put_fileupload.txt";
    public static final String DEFAULT_PUT_BODY = "Put File Upload verification.\r\n";
    public static final String ROBOTS_TXT_PATH = "/robots.txt";

    /**
     * Builds a PUT file upload request targeting the root path of the target host.
     */
    public static HttpRequest buildPutUploadRequest(HttpRequest baseRequest, String filename, String content) {
        if (baseRequest == null) {
            return null;
        }

        String targetPath = (filename == null || filename.isBlank()) ? DEFAULT_PUT_FILENAME : filename.trim();
        if (!targetPath.startsWith("/")) {
            targetPath = "/" + targetPath;
        }

        String bodyContent = (content == null) ? DEFAULT_PUT_BODY : content;
        byte[] bodyBytes = bodyContent.getBytes(StandardCharsets.UTF_8);

        HttpService service = baseRequest.httpService();
        String hostHeader = resolveHostHeader(baseRequest);

        StringBuilder sb = new StringBuilder();
        sb.append("PUT ").append(targetPath).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(hostHeader).append("\r\n");

        // Preserve client headers if present in base request
        copyHeaderIfPresent(baseRequest, sb, "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
        copyHeaderIfPresent(baseRequest, sb, "Authorization", null);
        copyHeaderIfPresent(baseRequest, sb, "Cookie", null);

        sb.append("Content-Type: text/plain\r\n");
        sb.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        sb.append(bodyContent);

        ByteArray reqBytes = ByteArray.byteArray(sb.toString().getBytes(StandardCharsets.UTF_8));
        return (service != null) ? HttpRequest.httpRequest(service, reqBytes) : HttpRequest.httpRequest(reqBytes);
    }

    /**
     * Convenience method using default test filename and body.
     */
    public static HttpRequest buildPutUploadRequest(HttpRequest baseRequest) {
        return buildPutUploadRequest(baseRequest, DEFAULT_PUT_FILENAME, DEFAULT_PUT_BODY);
    }

    /**
     * Builds a GET request probing /robots.txt at the web root of the target host.
     */
    public static HttpRequest buildRobotsTxtRequest(HttpRequest baseRequest) {
        return buildWebRootProbeRequest(baseRequest, ROBOTS_TXT_PATH);
    }

    /**
     * Builds a GET probe request for any root file/directory path.
     */
    public static HttpRequest buildWebRootProbeRequest(HttpRequest baseRequest, String path) {
        if (baseRequest == null) {
            return null;
        }

        String targetPath = (path == null || path.isBlank()) ? "/" : path.trim();
        if (!targetPath.startsWith("/")) {
            targetPath = "/" + targetPath;
        }

        HttpService service = baseRequest.httpService();
        String hostHeader = resolveHostHeader(baseRequest);

        StringBuilder sb = new StringBuilder();
        sb.append("GET ").append(targetPath).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(hostHeader).append("\r\n");

        copyHeaderIfPresent(baseRequest, sb, "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
        copyHeaderIfPresent(baseRequest, sb, "Authorization", null);
        copyHeaderIfPresent(baseRequest, sb, "Cookie", null);

        sb.append("Accept: text/plain, */*\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");

        ByteArray reqBytes = ByteArray.byteArray(sb.toString().getBytes(StandardCharsets.UTF_8));
        return (service != null) ? HttpRequest.httpRequest(service, reqBytes) : HttpRequest.httpRequest(reqBytes);
    }

    public static String resolveHostHeader(HttpRequest req) {
        if (req != null) {
            String host = req.headerValue("Host");
            if (host != null && !host.isBlank()) {
                return host.trim();
            }
            if (req.httpService() != null) {
                String h = req.httpService().host();
                int port = req.httpService().port();
                boolean secure = req.httpService().secure();
                if ((secure && port != 443) || (!secure && port != 80)) {
                    return h + ":" + port;
                }
                return h;
            }
        }
        return "localhost";
    }

    private static void copyHeaderIfPresent(HttpRequest src, StringBuilder sb, String headerName, String defaultValue) {
        if (src != null) {
            String val = src.headerValue(headerName);
            if (val != null && !val.isBlank()) {
                sb.append(headerName).append(": ").append(val.trim()).append("\r\n");
                return;
            }
        }
        if (defaultValue != null) {
            sb.append(headerName).append(": ").append(defaultValue).append("\r\n");
        }
    }
}
