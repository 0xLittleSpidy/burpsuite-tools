// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.List;

/**
 * Service querying Burp Proxy HTTP history to find recent JWT and session cookies,
 * and performing clean replacement into target HTTP requests without popups.
 */
public class ProxyAuthHistoryService_littlespidy {

    private final MontoyaApi api;

    public ProxyAuthHistoryService_littlespidy(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Finds the most recent JWT authorization header value from Proxy history.
     * Prefers matching target host if available; falls back to newest across history.
     */
    public String findRecentJwtHeader(HttpRequest targetRequest) {
        if (api == null || api.proxy() == null) {
            return null;
        }
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history == null || history.isEmpty()) {
            return null;
        }

        String targetHost = (targetRequest != null && targetRequest.httpService() != null)
                ? targetRequest.httpService().host() : null;

        String fallbackJwt = null;

        for (int i = history.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest() != null ? item.finalRequest() : item.request();
            if (req == null) continue;

            if (req.hasHeader("Authorization")) {
                String authVal = req.headerValue("Authorization");
                if (isJwtAuthHeader(authVal)) {
                    String itemHost = item.httpService() != null ? item.httpService().host() : null;
                    if (targetHost != null && targetHost.equalsIgnoreCase(itemHost)) {
                        return authVal;
                    }
                    if (fallbackJwt == null) {
                        fallbackJwt = authVal;
                    }
                }
            }
        }
        return fallbackJwt;
    }

    /**
     * Finds the most recent session Cookie header value from Proxy history.
     * Prefers matching target host if available; falls back to newest across history.
     */
    public String findRecentCookieHeader(HttpRequest targetRequest) {
        if (api == null || api.proxy() == null) {
            return null;
        }
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history == null || history.isEmpty()) {
            return null;
        }

        String targetHost = (targetRequest != null && targetRequest.httpService() != null)
                ? targetRequest.httpService().host() : null;

        String fallbackCookie = null;

        for (int i = history.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest() != null ? item.finalRequest() : item.request();
            if (req == null) continue;

            if (req.hasHeader("Cookie")) {
                String cookieVal = req.headerValue("Cookie");
                if (cookieVal != null && !cookieVal.trim().isEmpty()) {
                    String itemHost = item.httpService() != null ? item.httpService().host() : null;
                    if (targetHost != null && targetHost.equalsIgnoreCase(itemHost)) {
                        return cookieVal;
                    }
                    if (fallbackCookie == null) {
                        fallbackCookie = cookieVal;
                    }
                }
            }
        }
        return fallbackCookie;
    }

    /**
     * Replaces or adds the Authorization header into the target request.
     */
    public HttpRequest replaceJwt(HttpRequest request, String jwtAuthHeader) {
        if (request == null || jwtAuthHeader == null || jwtAuthHeader.trim().isEmpty()) {
            return request;
        }
        if (request.hasHeader("Authorization")) {
            return request.withUpdatedHeader("Authorization", jwtAuthHeader.trim());
        } else {
            return request.withAddedHeader("Authorization", jwtAuthHeader.trim());
        }
    }

    /**
     * Replaces or adds the Cookie header into the target request.
     */
    public HttpRequest replaceCookie(HttpRequest request, String cookieHeader) {
        if (request == null || cookieHeader == null || cookieHeader.trim().isEmpty()) {
            return request;
        }
        if (request.hasHeader("Cookie")) {
            return request.withUpdatedHeader("Cookie", cookieHeader.trim());
        } else {
            return request.withAddedHeader("Cookie", cookieHeader.trim());
        }
    }

    private boolean isJwtAuthHeader(String authVal) {
        if (authVal == null || authVal.trim().isEmpty()) {
            return false;
        }
        String trimmed = authVal.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = trimmed.substring(7).trim();
            return token.contains(".") || token.startsWith("eyJ");
        }
        return trimmed.contains("eyJ");
    }
}
