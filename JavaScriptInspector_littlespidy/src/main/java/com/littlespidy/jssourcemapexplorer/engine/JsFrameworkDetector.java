// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Front-end framework and bundler detector ported from js-recon.
 * Inspects URLs, chunk naming conventions, and body signatures to identify
 * target frameworks (Next.js, Nuxt.js, React, Vue.js, Svelte, Angular)
 * and development server indicators.
 *
 * @author littlespidy
 */
public final class JsFrameworkDetector {

    private JsFrameworkDetector() {}

    public record FrameworkResult(String name, boolean isDevServer, String evidence) {}

    public static FrameworkResult detect(String url, HttpResponse response) {
        String body = (response != null && response.body() != null && response.body().length() > 0)
            ? response.bodyToString()
            : "";
        return detect(url, body);
    }

    public static FrameworkResult detect(String url, String body) {
        if (url == null) url = "";
        String lowerUrl = url.toLowerCase();

        // 1. Next.js detection
        if (lowerUrl.contains("/_next/")) {
            boolean isDev = lowerUrl.contains("webpack-hmr") || lowerUrl.contains("on-demand-entries");
            return new FrameworkResult(isDev ? "Next.js (Dev)" : "Next.js", isDev, "URL path: /_next/");
        }

        // 2. Nuxt.js detection
        if (lowerUrl.contains("/_nuxt/")) {
            boolean isDev = lowerUrl.contains("@vite") || lowerUrl.contains("__webpack_hmr");
            return new FrameworkResult(isDev ? "Nuxt.js (Dev)" : "Nuxt.js", isDev, "URL path: /_nuxt/");
        }

        // 3. Svelte / SvelteKit detection
        if (lowerUrl.contains("/_app/immutable/") || lowerUrl.contains("/_app/version.json") || lowerUrl.contains("svelte")) {
            boolean isDev = lowerUrl.contains("@vite/client");
            return new FrameworkResult(isDev ? "SvelteKit (Dev)" : "Svelte", isDev, "URL path: /_app/immutable/");
        }

        // 4. Vite React / Dev server detection
        if (lowerUrl.contains("/@react-refresh") || lowerUrl.contains("/@vite/client")) {
            return new FrameworkResult("React (Vite Dev)", true, "Vite HMR runtime URL");
        }

        // 5. Inspect response body (if available)
        if (body != null && !body.isEmpty()) {
            int checkLimit = Math.min(body.length(), 50_000);
            String snippet = body.substring(0, checkLimit);

            // Next.js markers
            if (snippet.contains("__NEXT_DATA__") || snippet.contains("next/router") || snippet.contains("__next")) {
                return new FrameworkResult("Next.js", false, "Body signature: __NEXT_DATA__");
            }

            // Nuxt.js markers
            if (snippet.contains("window.__NUXT__") || snippet.contains("__NUXT_DATA__")) {
                return new FrameworkResult("Nuxt.js", false, "Body signature: __NUXT__");
            }

            // Vue.js markers
            if (snippet.contains("data-v-") || snippet.contains("Vue.component") || snippet.contains("__vue__")) {
                return new FrameworkResult("Vue.js", false, "Body signature: data-v-");
            }

            // Angular markers
            if (snippet.contains("ng-version") || snippet.contains("ng-reflect-") || lowerUrl.contains("polyfills.js") && snippet.contains("zone.js")) {
                return new FrameworkResult("Angular", false, "Body signature: ng-version / Zone.js");
            }

            // React markers
            if (snippet.contains("react-dom") || snippet.contains("React.createElement") || snippet.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__")) {
                return new FrameworkResult("React", false, "Body signature: React runtime");
            }
        }

        // Default: generic or unclassified
        return new FrameworkResult("-", false, "No framework pattern matched");
    }

    public static String detectFramework(String url, String body) {
        return detect(url, body).name();
    }

    public static String detectFramework(String url, HttpResponse response) {
        return detect(url, response).name();
    }
}
