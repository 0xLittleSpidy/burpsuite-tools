// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Normalizes URLs into deduplication signatures following the reKover methodology:
 * path + comma-separated sorted query parameter keys (values stripped).
 *
 * <p>Example:
 * {@code https://target.com/api/users?sort=asc&id=123} -> {@code /api/users::id,sort}
 *
 * @author littlespidy
 */
public record UrlSignature_littlespidy(
    String path,
    String paramKeys,
    String signature,
    String originalUrl
) {
    public static UrlSignature_littlespidy fromUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return new UrlSignature_littlespidy("/", "", "/::", "");
        }

        String u = rawUrl.trim();
        // Drop scheme + host:port if full URL
        if (u.startsWith("http://") || u.startsWith("https://")) {
            int slashIdx = u.indexOf('/', u.indexOf("://") + 3);
            u = (slashIdx != -1) ? u.substring(slashIdx) : "/";
        }

        if (!u.startsWith("/")) {
            u = "/" + u;
        }

        String pathPart;
        String queryPart = "";

        int qIdx = u.indexOf('?');
        if (qIdx != -1) {
            pathPart = u.substring(0, qIdx);
            queryPart = u.substring(qIdx + 1);
        } else {
            pathPart = u;
        }

        // Clean trailing slash
        while (pathPart.endsWith("/") && pathPart.length() > 1) {
            pathPart = pathPart.substring(0, pathPart.length() - 1);
        }
        if (pathPart.isEmpty()) {
            pathPart = "/";
        }

        // Extract and sort parameter keys
        String sortedKeys = "";
        if (!queryPart.isEmpty()) {
            Set<String> keys = new TreeSet<>();
            String[] pairs = queryPart.split("&");
            for (String pair : pairs) {
                if (pair.isBlank()) continue;
                String k = pair.split("=")[0].trim();
                try {
                    k = URLDecoder.decode(k, StandardCharsets.UTF_8);
                } catch (Exception ignored) {}
                if (!k.isEmpty()) {
                    keys.add(k);
                }
            }
            sortedKeys = String.join(",", keys);
        }

        String sig = pathPart + "::" + sortedKeys;
        return new UrlSignature_littlespidy(pathPart, sortedKeys, sig, rawUrl);
    }
}
