package com.littlespidy.convertposttoget.engine;

import com.littlespidy.convertposttoget.model.ConfiguredHeader;
import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Core converter that transforms POST requests into GET requests
 * by migrating URL-encoded, JSON, multipart, or raw body parameters into query parameters,
 * stripping body headers, and applying custom auth/session headers.
 *
 * @author littlespidy
 */
public class PostToGetConverter {
    private final MontoyaApi api;
    private final ConvertPostToGetConfig config;

    public PostToGetConverter(MontoyaApi api, ConvertPostToGetConfig config) {
        this.api = api;
        this.config = config;
    }

    public HttpRequest convertPostToGet(HttpRequest originalRequest, List<ConfiguredHeader> sessionHeaders) {
        if (originalRequest == null) return null;

        String body = originalRequest.bodyToString().trim();
        String contentType = originalRequest.headerValue("Content-Type");
        if (contentType == null) contentType = "";
        contentType = contentType.toLowerCase();

        String path = originalRequest.path();
        if (path == null || path.isEmpty()) path = "/";

        String existingQuery = "";
        String basePath = path;
        int qIdx = path.indexOf('?');
        if (qIdx >= 0) {
            basePath = path.substring(0, qIdx);
            existingQuery = path.substring(qIdx + 1);
        }

        String bodyParams = "";

        if (contentType.contains("application/x-www-form-urlencoded")) {
            bodyParams = body;
        } else if (contentType.contains("application/json")) {
            StringBuilder sb = new StringBuilder();
            String stripped = body;
            if (stripped.startsWith("{") && stripped.endsWith("}")) {
                stripped = stripped.substring(1, stripped.length() - 1).trim();
            }

            String[] pairs = stripped.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            for (String pair : pairs) {
                pair = pair.trim();
                int colonIdx = pair.indexOf(':');
                if (colonIdx < 0) continue;

                String key = pair.substring(0, colonIdx).trim().replaceAll("^\"|\"$", "");
                String value = pair.substring(colonIdx + 1).trim().replaceAll("^\"|\"$", "");

                if (sb.length() > 0) sb.append("&");
                sb.append(urlEncode(key)).append("=").append(urlEncode(value));
            }
            bodyParams = sb.toString();
        } else if (!body.isEmpty()) {
            bodyParams = urlEncode(body);
        }

        // Assemble new query string
        StringBuilder newPath = new StringBuilder(basePath);
        if (!existingQuery.isEmpty() || !bodyParams.isEmpty()) {
            newPath.append("?");
            if (!existingQuery.isEmpty()) {
                newPath.append(existingQuery);
                if (!bodyParams.isEmpty()) newPath.append("&");
            }
            if (!bodyParams.isEmpty()) {
                newPath.append(bodyParams);
            }
        }

        HttpRequest getRequest = originalRequest
            .withMethod("GET")
            .withPath(newPath.toString())
            .withBody("");

        if (config.isUpdateContentTypeHeaders()) {
            if (getRequest.hasHeader("Content-Type")) {
                getRequest = getRequest.withRemovedHeader("Content-Type");
            }
            if (getRequest.hasHeader("Content-Length")) {
                getRequest = getRequest.withRemovedHeader("Content-Length");
            }
        }

        // Apply custom session cookies, Authorization headers, or API keys
        if (sessionHeaders != null && !sessionHeaders.isEmpty()) {
            for (ConfiguredHeader ch : sessionHeaders) {
                if (getRequest.hasHeader(ch.name())) {
                    getRequest = getRequest.withUpdatedHeader(ch.name(), ch.value());
                } else {
                    getRequest = getRequest.withAddedHeader(ch.name(), ch.value());
                }
            }
        }

        return getRequest;
    }

    public HttpRequest applySessionHeaders(HttpRequest request, List<ConfiguredHeader> sessionHeaders) {
        if (request == null || sessionHeaders == null || sessionHeaders.isEmpty()) {
            return request;
        }

        HttpRequest mutated = request;
        for (ConfiguredHeader ch : sessionHeaders) {
            if (mutated.hasHeader(ch.name())) {
                mutated = mutated.withUpdatedHeader(ch.name(), ch.value());
            } else {
                mutated = mutated.withAddedHeader(ch.name(), ch.value());
            }
        }
        return mutated;
    }

    private String urlEncode(String text) {
        try {
            return URLEncoder.encode(text, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return text;
        }
    }
}
