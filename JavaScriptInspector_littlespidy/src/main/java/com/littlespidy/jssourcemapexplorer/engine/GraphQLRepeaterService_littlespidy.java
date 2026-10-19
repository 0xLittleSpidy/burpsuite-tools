// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredGraphQLOperation;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Service to synthesize and dispatch GraphQL HTTP requests (both POST and GET)
 * to Burp Suite Repeater via the Montoya API.
 *
 * @author littlespidy
 */
public class GraphQLRepeaterService_littlespidy {

    private final MontoyaApi api;

    public GraphQLRepeaterService_littlespidy(MontoyaApi api) {
        this.api = api;
    }

    public void sendToRepeaterPost(DiscoveredGraphQLOperation op, JsFileEntry entry) {
        if (op == null || api == null) return;

        String targetUrl = resolveTargetUrl(op, entry);
        String jsonPayload = buildJsonRequestBody(op.queryBody(), op.variablesJson());
        String tabTitle = "GQL: " + (op.operationName() != null ? op.operationName() : "Operation");

        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl)
                .withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json, text/plain, */*")
                .withBody(jsonPayload);

            // Copy cookies/authorization if available from the source script request
            if (entry != null && entry.getRequest() != null) {
                String cookie = entry.getRequest().headerValue("Cookie");
                if (cookie != null && !cookie.isBlank()) {
                    request = request.withHeader("Cookie", cookie);
                }
                String auth = entry.getRequest().headerValue("Authorization");
                if (auth != null && !auth.isBlank()) {
                    request = request.withHeader("Authorization", auth);
                }
            }

            api.repeater().sendToRepeater(request, tabTitle);
        } catch (Exception ex) {
            api.logging().logToError("Error sending GraphQL POST request to Repeater: " + ex.getMessage());
        }
    }

    public void sendToRepeaterGet(DiscoveredGraphQLOperation op, JsFileEntry entry) {
        if (op == null || api == null) return;

        String baseTargetUrl = resolveTargetUrl(op, entry);
        String tabTitle = "GQL-GET: " + (op.operationName() != null ? op.operationName() : "Operation");

        try {
            String queryEncoded = URLEncoder.encode(op.queryBody(), StandardCharsets.UTF_8);
            String varsEncoded = URLEncoder.encode(op.variablesJson() != null ? op.variablesJson() : "{}", StandardCharsets.UTF_8);
            String separator = baseTargetUrl.contains("?") ? "&" : "?";
            String fullGetUrl = baseTargetUrl + separator + "query=" + queryEncoded + "&variables=" + varsEncoded;

            HttpRequest request = HttpRequest.httpRequestFromUrl(fullGetUrl)
                .withMethod("GET")
                .withHeader("Accept", "application/json, text/plain, */*");

            if (entry != null && entry.getRequest() != null) {
                String cookie = entry.getRequest().headerValue("Cookie");
                if (cookie != null && !cookie.isBlank()) {
                    request = request.withHeader("Cookie", cookie);
                }
                String auth = entry.getRequest().headerValue("Authorization");
                if (auth != null && !auth.isBlank()) {
                    request = request.withHeader("Authorization", auth);
                }
            }

            api.repeater().sendToRepeater(request, tabTitle);
        } catch (Exception ex) {
            api.logging().logToError("Error sending GraphQL GET request to Repeater: " + ex.getMessage());
        }
    }

    private String resolveTargetUrl(DiscoveredGraphQLOperation op, JsFileEntry entry) {
        String endpoint = op.associatedEndpoint();
        if (endpoint != null && (endpoint.startsWith("http://") || endpoint.startsWith("https://"))) {
            return endpoint;
        }

        String path = (endpoint != null && endpoint.startsWith("/")) ? endpoint : "/graphql";

        if (entry != null && entry.getRequest() != null && entry.getRequest().httpService() != null) {
            HttpService svc = entry.getRequest().httpService();
            String protocol = svc.secure() ? "https" : "http";
            String port = ((svc.secure() && svc.port() == 443) || (!svc.secure() && svc.port() == 80))
                ? "" : ":" + svc.port();
            return protocol + "://" + svc.host() + port + path;
        }

        if (op.sourceLocation() != null && (op.sourceLocation().startsWith("http://") || op.sourceLocation().startsWith("https://"))) {
            try {
                URI uri = URI.create(op.sourceLocation());
                String protocol = uri.getScheme() != null ? uri.getScheme() : "https";
                String host = uri.getHost() != null ? uri.getHost() : "localhost";
                int port = uri.getPort();
                String portStr = (port == -1 || (protocol.equals("https") && port == 443) || (protocol.equals("http") && port == 80))
                    ? "" : ":" + port;
                return protocol + "://" + host + portStr + path;
            } catch (Exception ignored) {}
        }

        return "https://localhost" + path;
    }

    private String buildJsonRequestBody(String query, String variablesJson) {
        String escapedQuery = escapeJsonString(query);
        String vars = (variablesJson != null && !variablesJson.isBlank()) ? variablesJson.trim() : "{}";
        return "{\n  \"query\": \"" + escapedQuery + "\",\n  \"variables\": " + vars + "\n}";
    }

    private String escapeJsonString(String str) {
        if (str == null) return "";
        StringBuilder sb = new StringBuilder(str.length() + 32);
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.toString();
    }
}
