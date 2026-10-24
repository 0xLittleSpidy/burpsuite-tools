// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.graphqlcop.model.HttpLogEntry_littlespidy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public class HttpHelper_littlespidy {
    private static final AtomicInteger LOG_ID_GEN = new AtomicInteger(1);
    private static final SimpleDateFormat TIME_FMT = new SimpleDateFormat("HH:mm:ss", Locale.US);

    public static boolean isValidUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        try {
            URI uri = URI.create(url.trim());
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                return false;
            }
            return uri.getHost() != null && !uri.getHost().trim().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    public static HttpRequest createBaseRequest(String targetUrl, String customHeaders) {
        if (!isValidUrl(targetUrl)) {
            return null;
        }
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(targetUrl.trim());
            if (customHeaders != null && !customHeaders.trim().isEmpty()) {
                String[] lines = customHeaders.split("\\r?\\n");
                for (String line : lines) {
                    int colon = line.indexOf(':');
                    if (colon > 0) {
                        String name = line.substring(0, colon).trim();
                        String value = line.substring(colon + 1).trim();
                        if (!name.isEmpty()) {
                            req = req.withHeader(name, value);
                        }
                    }
                }
            }
            return req;
        } catch (Exception e) {
            return null;
        }
    }

    public static HttpRequestResponse sendJsonPost(MontoyaApi api, String targetUrl, String customHeaders,
                                                   String jsonBody, String probeName,
                                                   Consumer<HttpLogEntry_littlespidy> logConsumer) {
        if (!isValidUrl(targetUrl)) {
            return null;
        }

        HttpRequest baseReq = createBaseRequest(targetUrl, customHeaders);
        if (baseReq == null) {
            return null;
        }

        HttpRequest req = baseReq
                .withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json")
                .withBody(jsonBody);

        long start = System.currentTimeMillis();
        HttpRequestResponse responsePair = null;
        try {
            responsePair = api.http().sendRequest(req);
        } catch (Exception e) {
            return null;
        }
        long duration = System.currentTimeMillis() - start;

        if (responsePair != null && logConsumer != null) {
            HttpResponse resp = responsePair.response();
            int statusCode = resp != null ? resp.statusCode() : 0;
            int len = resp != null ? resp.body().length() : 0;

            String reqB64 = Base64.getEncoder().encodeToString(responsePair.request().toByteArray().getBytes());
            String respB64 = resp != null ? Base64.getEncoder().encodeToString(resp.toByteArray().getBytes()) : "";

            HttpLogEntry_littlespidy entry = new HttpLogEntry_littlespidy(
                    LOG_ID_GEN.getAndIncrement(),
                    TIME_FMT.format(new Date()),
                    "POST",
                    targetUrl,
                    probeName,
                    statusCode,
                    len,
                    duration,
                    reqB64,
                    respB64
            );
            logConsumer.accept(entry);
        }
        return responsePair;
    }

    public static HttpRequestResponse sendCustom(MontoyaApi api, HttpRequest req, String probeName,
                                                 Consumer<HttpLogEntry_littlespidy> logConsumer) {
        if (req == null) {
            return null;
        }
        long start = System.currentTimeMillis();
        HttpRequestResponse responsePair = null;
        try {
            responsePair = api.http().sendRequest(req);
        } catch (Exception e) {
            return null;
        }
        long duration = System.currentTimeMillis() - start;

        if (responsePair != null && logConsumer != null) {
            HttpResponse resp = responsePair.response();
            int statusCode = resp != null ? resp.statusCode() : 0;
            int len = resp != null ? resp.body().length() : 0;

            String reqB64 = Base64.getEncoder().encodeToString(responsePair.request().toByteArray().getBytes());
            String respB64 = resp != null ? Base64.getEncoder().encodeToString(resp.toByteArray().getBytes()) : "";

            HttpLogEntry_littlespidy entry = new HttpLogEntry_littlespidy(
                    LOG_ID_GEN.getAndIncrement(),
                    TIME_FMT.format(new Date()),
                    req.method(),
                    req.url(),
                    probeName,
                    statusCode,
                    len,
                    duration,
                    reqB64,
                    respB64
            );
            logConsumer.accept(entry);
        }
        return responsePair;
    }

    public static String getResponseBody(HttpRequestResponse pair) {
        if (pair == null || pair.response() == null) {
            return "";
        }
        return new String(pair.response().body().getBytes(), StandardCharsets.UTF_8);
    }
}
