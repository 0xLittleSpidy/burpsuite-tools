// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.wayback.config.CommonConfig_littlespidy;

import java.io.BufferedReader;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class WaybackCdxClient_littlespidy {

    private final MontoyaApi api;
    private final CommonConfig_littlespidy config;

    public WaybackCdxClient_littlespidy(MontoyaApi api, CommonConfig_littlespidy config) {
        this.api = api;
        this.config = config != null ? config : new CommonConfig_littlespidy();
    }

    public List<String> fetchWaybackUrls(String domain, boolean autoSubdomains, StatusCallback callback) {
        if (domain == null || domain.isBlank()) {
            return Collections.emptyList();
        }

        String targetPattern = autoSubdomains ? "*." + domain.trim() + "/*" : domain.trim() + "/*";
        String template = config.getCdxUrlTemplate();
        String cdxUrl = template.replace("{DOMAIN}", targetPattern);

        int maxRetries = config.getCdxRetries();
        int retryDelaySec = config.getCdxRetryDelaySec();
        String userAgent = config.getUserAgent();

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            if (callback != null) {
                callback.onStatus("Querying Wayback CDX for " + domain + " (Attempt " + attempt + " of " + maxRetries + ")...");
            }

            try {
                String responseBody = executeQuery(cdxUrl, userAgent);
                if (responseBody != null && !responseBody.isBlank()) {
                    List<String> lines = new ArrayList<>();
                    try (BufferedReader reader = new BufferedReader(new StringReader(responseBody))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            String trimmed = line.trim();
                            if (!trimmed.isEmpty()) {
                                lines.add(trimmed);
                            }
                        }
                    }
                    if (callback != null) {
                        callback.onStatus("Retrieved " + lines.size() + " archived records from Wayback CDX.");
                    }
                    return lines;
                }
            } catch (Exception ex) {
                if (callback != null) {
                    callback.onStatus("CDX query error (Attempt " + attempt + "): " + ex.getMessage());
                }
                if (attempt < maxRetries) {
                    try {
                        Thread.sleep(retryDelaySec * 1000L * attempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }

        return Collections.emptyList();
    }

    private String executeQuery(String urlString, String userAgent) throws Exception {
        if (api != null && config.isHonorBurpProxy()) {
            URI uri = URI.create(urlString);
            String host = uri.getHost();
            int port = uri.getPort() != -1 ? uri.getPort() : (uri.getScheme().equalsIgnoreCase("https") ? 443 : 80);
            boolean isSecure = uri.getScheme().equalsIgnoreCase("https");

            String pathAndQuery = uri.getRawPath();
            if (uri.getRawQuery() != null) {
                pathAndQuery += "?" + uri.getRawQuery();
            }

            HttpService service = HttpService.httpService(host, port, isSecure);
            HttpRequest burpReq = HttpRequest.httpRequest(service,
                    "GET " + pathAndQuery + " HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "User-Agent: " + userAgent + "\r\n" +
                    "Accept: */*\r\n" +
                    "Connection: close\r\n\r\n");

            HttpResponse burpResp = api.http().sendRequest(burpReq).response();
            if (burpResp != null && burpResp.statusCode() == 200) {
                return burpResp.bodyToString();
            }
        }

        // Standalone fallback using standard Java HttpClient
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(urlString))
                .header("User-Agent", userAgent)
                .header("Accept", "*/*")
                .timeout(Duration.ofSeconds(20))
                .GET()
                .build();

        java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString());
        if (resp.statusCode() == 200) {
            return resp.body();
        }

        return null;
    }

    public interface StatusCallback {
        void onStatus(String message);
    }
}
