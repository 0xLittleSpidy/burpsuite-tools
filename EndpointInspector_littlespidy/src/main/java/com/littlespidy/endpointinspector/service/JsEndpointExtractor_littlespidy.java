// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JavaScript-aware endpoint extractor ported from the reKover methodology.
 * Surfaces same-origin paths, relative API routes, HTTP client arguments,
 * and template literals from response bodies and JavaScript files.
 *
 * @author littlespidy
 */
public final class JsEndpointExtractor_littlespidy {

    private static final Pattern QUOTED_API_PATH = Pattern.compile(
        "[\"']((?:api|v[0-9]+|rest|graphql|internal)/[a-zA-Z0-9/_.-]+)[\"']", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern HTTP_CLIENT_ARG = Pattern.compile(
        "(?:fetch|\\.get|\\.post|\\.put|\\.delete|\\.patch|\\.open)\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern TEMPLATE_LITERAL_PATH = Pattern.compile(
        "`([^`]+)`"
    );

    private static final Pattern HTML_ATTRIBUTES = Pattern.compile(
        "(?:href|src|action)=[\"']([^\"'#?][^\"']*)[\"']", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern QUOTED_ROOT_PATHS = Pattern.compile(
        "[\"'](/[a-zA-Z0-9/_.-]{2,})[\"']"
    );

    private JsEndpointExtractor_littlespidy() {}

    /**
     * Extracts all endpoints and relative API paths from HTML or JavaScript response content.
     */
    public static Set<String> extractEndpoints(String body, boolean isJavaScript) {
        if (body == null || body.isBlank()) {
            return Collections.emptySet();
        }

        Set<String> discovered = new TreeSet<>();

        // 1. Standard HTML and Quoted Root Paths
        Matcher mAttr = HTML_ATTRIBUTES.matcher(body);
        while (mAttr.find()) {
            String path = mAttr.group(1).trim();
            if (path.startsWith("/") || path.startsWith("http://") || path.startsWith("https://")) {
                discovered.add(normalizeEndpoint(path));
            }
        }

        Matcher mQuoted = QUOTED_ROOT_PATHS.matcher(body);
        while (mQuoted.find()) {
            discovered.add(normalizeEndpoint(mQuoted.group(1)));
        }

        // 2. JavaScript-aware extraction
        if (isJavaScript) {
            Matcher mApi = QUOTED_API_PATH.matcher(body);
            while (mApi.find()) {
                String path = mApi.group(1).trim();
                discovered.add(normalizeEndpoint(path));
            }

            Matcher mClient = HTTP_CLIENT_ARG.matcher(body);
            while (mClient.find()) {
                String target = mClient.group(1).trim();
                if (!target.startsWith("http://") && !target.startsWith("https://")) {
                    discovered.add(normalizeEndpoint(target));
                }
            }

            Matcher mTemplate = TEMPLATE_LITERAL_PATH.matcher(body);
            while (mTemplate.find()) {
                String template = mTemplate.group(1).trim();
                // Strip dynamic interpolation e.g. /api/users/${id} -> /api/users/
                int interpIdx = template.indexOf("${");
                if (interpIdx != -1) {
                    template = template.substring(0, interpIdx);
                }
                template = template.trim();
                if (template.startsWith("/") && template.length() >= 2) {
                    discovered.add(normalizeEndpoint(template));
                }
            }
        }

        discovered.removeIf(p -> p.isBlank() || p.equals("/"));
        return discovered;
    }

    private static String normalizeEndpoint(String path) {
        String p = path.trim();
        if (p.startsWith("http://") || p.startsWith("https://")) {
            return p;
        }
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        while (p.endsWith("/") && p.length() > 1) {
            p = p.substring(0, p.length() - 1);
        }
        return p;
    }
}
