// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scope.Scope;
import com.littlespidy.quickhelper.model.ExtractionOptions_littlespidy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Service to extract unique domain names or domains with HTTP schema from Burp Suite site map.
 */
public class DomainExtractorService_littlespidy {

    private final MontoyaApi api;
    private final ClipboardService_littlespidy clipboardService;
    private final ExecutorService executorService;

    public DomainExtractorService_littlespidy(MontoyaApi api, ClipboardService_littlespidy clipboardService) {
        this.api = api;
        this.clipboardService = clipboardService;
        this.executorService = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "QuickHelper-Worker");
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Extracts domains according to the given options from the current Burp Suite site map.
     *
     * @param options extraction options
     * @return sorted list of unique domain names or URLs
     */
    public List<String> extractDomains(ExtractionOptions_littlespidy options) {
        if (api == null || api.siteMap() == null) {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> items = api.siteMap().requestResponses();
        Scope scope = api.scope();
        return extractDomains(items, scope, options);
    }

    /**
     * Pure extraction method for testability and flexibility.
     *
     * @param items   list of request-response pairs
     * @param scope   burp scope (nullable if not filtering in-scope)
     * @param options extraction options
     * @return sorted list of unique domains or URLs
     */
    public List<String> extractDomains(List<HttpRequestResponse> items, Scope scope, ExtractionOptions_littlespidy options) {
        if (items == null || items.isEmpty()) {
            return Collections.emptyList();
        }

        Set<String> uniqueEntries = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

        for (HttpRequestResponse item : items) {
            if (item == null || item.request() == null) {
                continue;
            }

            if (options.isInScopeOnly() && scope != null) {
                String url = item.request().url();
                if (url == null || !scope.isInScope(url)) {
                    continue;
                }
            }

            HttpService service = item.request().httpService();
            if (service == null) {
                continue;
            }

            String host = service.host();
            if (host == null || host.trim().isEmpty()) {
                continue;
            }

            host = host.trim().toLowerCase();

            if (options.isIncludeSchema()) {
                String protocol = service.secure() ? "https" : "http";
                int port = service.port();
                boolean isDefaultPort = (service.secure() && port == 443) || (!service.secure() && port == 80);

                String formattedUrl;
                if (isDefaultPort || port <= 0) {
                    formattedUrl = protocol + "://" + host;
                } else {
                    formattedUrl = protocol + "://" + host + ":" + port;
                }
                uniqueEntries.add(formattedUrl);
            } else {
                uniqueEntries.add(host);
            }
        }

        return new ArrayList<>(uniqueEntries);
    }

    /**
     * Extracts domains in the background, copies them to the clipboard, and logs progress to Burp.
     *
     * @param options     extraction options
     * @param actionLabel descriptive action label for notifications
     * @return CompletableFuture holding the extracted items
     */
    public CompletableFuture<List<String>> extractAndCopyAsync(ExtractionOptions_littlespidy options, String actionLabel) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (api != null && api.logging() != null) {
                    api.logging().logToOutput("Quick Helper: Starting " + actionLabel + " from site map...");
                }

                List<String> domains = extractDomains(options);
                String joined = String.join(System.lineSeparator(), domains);

                boolean copied = clipboardService.copyToClipboard(joined);

                String summary = "Quick Helper: " + actionLabel + " finished. Found "
                        + domains.size() + " unique entry(ies). Clipboard copy: "
                        + (copied ? "Success" : "Failed / Headless");

                if (api != null && api.logging() != null) {
                    api.logging().logToOutput(summary);
                    api.logging().raiseInfoEvent(summary);
                }

                return domains;
            } catch (Exception e) {
                if (api != null && api.logging() != null) {
                    api.logging().logToError("Quick Helper error during " + actionLabel + ": " + e.getMessage(), e);
                    api.logging().raiseErrorEvent("Quick Helper error during " + actionLabel + ": " + e.getMessage());
                }
                return Collections.emptyList();
            }
        }, executorService);
    }

    /**
     * Shuts down background executor.
     */
    public void shutdown() {
        executorService.shutdownNow();
    }
}
