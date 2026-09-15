// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.littlespidy.headerinspector.cache.model.CacheDataStore;
import com.littlespidy.headerinspector.cache.model.CacheEntry;
import com.littlespidy.headerinspector.cache.ui.CacheInspectorTab;
import com.littlespidy.headerinspector.collector.model.HeaderCollectorDataStore;
import com.littlespidy.headerinspector.collector.ui.HeaderCollectorTab;
import com.littlespidy.headerinspector.csp.model.CSPDataStore;
import com.littlespidy.headerinspector.csp.model.CSPEntry;
import com.littlespidy.headerinspector.csp.model.CSPParser;
import com.littlespidy.headerinspector.csp.ui.CSPInspectorTab;
import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.hsts.model.HSTSEntry;
import com.littlespidy.headerinspector.hsts.model.HSTSParser;
import com.littlespidy.headerinspector.hsts.ui.HSTSInspectorTab;
import com.littlespidy.headerinspector.method.model.MethodCollectorDataStore;
import com.littlespidy.headerinspector.method.ui.MethodCollectorTab;
import com.littlespidy.headerinspector.status.model.StatusCollectorDataStore;
import com.littlespidy.headerinspector.status.ui.StatusCollectorTab;

import javax.swing.*;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Central coordinator for on-demand Proxy history ingestion across all tabs.
 * When triggered from ANY tab, it performs a single unified, non-blocking background
 * pass over proxy traffic, safely pre-filtering out-of-scope items to prevent freezes,
 * populating all 6 inspectors simultaneously, and refreshing all views on the EDT.
 *
 * @author littlespidy
 */
public class ProxyHistoryCoordinator {

    private final MontoyaApi api;
    private final HeaderCollectorDataStore headerCollectorDataStore;
    private final MethodCollectorDataStore methodCollectorDataStore;
    private final StatusCollectorDataStore statusCollectorDataStore;
    private final CacheDataStore cacheDataStore;
    private final CSPDataStore cspDataStore;
    private final HSTSDataStore hstsDataStore;

    private HeaderCollectorTab headerCollectorTab;
    private MethodCollectorTab methodCollectorTab;
    private StatusCollectorTab statusCollectorTab;
    private CacheInspectorTab cacheInspectorTab;
    private CSPInspectorTab cspInspectorTab;
    private HSTSInspectorTab hstsInspectorTab;

    private final AtomicBoolean isLoading = new AtomicBoolean(false);

    public record IngestionResult(
        List<CacheEntry> cacheEntries,
        List<CSPEntry> cspEntries,
        List<HSTSEntry> hstsEntries,
        int processedCount,
        int skippedCount
    ) {}

    public ProxyHistoryCoordinator(
            MontoyaApi api,
            HeaderCollectorDataStore headerCollectorDataStore,
            MethodCollectorDataStore methodCollectorDataStore,
            StatusCollectorDataStore statusCollectorDataStore,
            CacheDataStore cacheDataStore,
            CSPDataStore cspDataStore,
            HSTSDataStore hstsDataStore) {
        this.api = api;
        this.headerCollectorDataStore = headerCollectorDataStore;
        this.methodCollectorDataStore = methodCollectorDataStore;
        this.statusCollectorDataStore = statusCollectorDataStore;
        this.cacheDataStore = cacheDataStore;
        this.cspDataStore = cspDataStore;
        this.hstsDataStore = hstsDataStore;
    }

    public void registerTabs(
            HeaderCollectorTab headerCollectorTab,
            MethodCollectorTab methodCollectorTab,
            StatusCollectorTab statusCollectorTab,
            CacheInspectorTab cacheInspectorTab,
            CSPInspectorTab cspInspectorTab,
            HSTSInspectorTab hstsInspectorTab) {
        this.headerCollectorTab = headerCollectorTab;
        this.methodCollectorTab = methodCollectorTab;
        this.statusCollectorTab = statusCollectorTab;
        this.cacheInspectorTab = cacheInspectorTab;
        this.cspInspectorTab = cspInspectorTab;
        this.hstsInspectorTab = hstsInspectorTab;
    }

    public void loadAllProxyHistory(boolean inScopeOnly) {
        if (isLoading.getAndSet(true)) {
            return;
        }

        String msg = "Ingesting Proxy history across all inspectors (" + (inScopeOnly ? "in-scope only" : "all items") + ")...";
        setAllTabsLoading(true, msg);

        SwingWorker<IngestionResult, Void> worker = new SwingWorker<>() {
            @Override
            protected IngestionResult doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                Map<String, CacheEntry> uniqueCache = new LinkedHashMap<>();
                Map<String, CSPEntry> uniqueCSP = new LinkedHashMap<>();
                Map<String, HSTSEntry> uniqueHSTS = new LinkedHashMap<>();

                int processed = 0;
                int skipped = 0;

                for (ProxyHttpRequestResponse item : history) {
                    if (item == null || item.request() == null) continue;

                    String url = item.request().url();
                    // Fast pre-filter: discard out-of-scope traffic early to prevent UI lag & memory bloat
                    if (inScopeOnly && url != null && !api.scope().isInScope(url)) {
                        skipped++;
                        continue;
                    }

                    // 1. Ingest into Header Collector and Method Collector
                    headerCollectorDataStore.ingest(item);
                    methodCollectorDataStore.ingest(item);
                    processed++;

                    // 2. Ingest into Status Collector, Cache, CSP, and HSTS if response exists
                    if (item.hasResponse() && item.response() != null) {
                        statusCollectorDataStore.ingest(item);
                        var resp = item.response();
                        String host = item.request().httpService() != null ? item.request().httpService().host() : "";
                        String path = item.request().path() != null ? item.request().path() : "/";
                        String method = item.request().method() != null ? item.request().method().toUpperCase() : "GET";
                        String dedupeKey = method + " " + url;
                        ZonedDateTime now = ZonedDateTime.now();

                        // Cache Entry
                        if (!uniqueCache.containsKey(dedupeKey)) {
                            CacheEntry cacheEntry = new CacheEntry(
                                cacheDataStore.nextId(), url, host, path, method,
                                resp.statusCode(),
                                resp.headerValue("Content-Type")        != null ? resp.headerValue("Content-Type")        : "",
                                resp.headerValue("Cache-Control")       != null ? resp.headerValue("Cache-Control")       : "",
                                resp.headerValue("Pragma")              != null ? resp.headerValue("Pragma")              : "",
                                resp.headerValue("Expires")             != null ? resp.headerValue("Expires")             : "",
                                resp.headerValue("Age")                 != null ? resp.headerValue("Age")                 : "",
                                resp.headerValue("ETag")                != null ? resp.headerValue("ETag")                : "",
                                resp.headerValue("Last-Modified")       != null ? resp.headerValue("Last-Modified")       : "",
                                resp.headerValue("Vary")                != null ? resp.headerValue("Vary")                : "",
                                resp.headerValue("X-Cache")             != null ? resp.headerValue("X-Cache")             : "",
                                resp.headerValue("X-Cache-Hits")        != null ? resp.headerValue("X-Cache-Hits")        : "",
                                resp.headerValue("CDN-Cache-Control")   != null ? resp.headerValue("CDN-Cache-Control")   : "",
                                resp.headerValue("Surrogate-Control")   != null ? resp.headerValue("Surrogate-Control")   : "",
                                resp.headerValue("CF-Cache-Status")     != null ? resp.headerValue("CF-Cache-Status")     : "",
                                item.request(), resp, now
                            );
                            uniqueCache.put(dedupeKey, cacheEntry);
                        }

                        // CSP Entry
                        if (!uniqueCSP.containsKey(dedupeKey)) {
                            String csp = resp.headerValue("Content-Security-Policy");
                            String cspRo = resp.headerValue("Content-Security-Policy-Report-Only");
                            String xCsp = resp.headerValue("X-Content-Security-Policy");
                            String xWebKit = resp.headerValue("X-WebKit-CSP");
                            String effectivePolicy = (csp != null && !csp.isEmpty()) ? csp : cspRo;
                            Map<String, List<String>> parsedDirectives = CSPParser.parsePolicy(effectivePolicy);

                            CSPEntry cspEntry = new CSPEntry(
                                cspDataStore.nextId(), url, host, path, method,
                                resp.statusCode(),
                                resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "",
                                csp != null ? csp : "",
                                cspRo != null ? cspRo : "",
                                xCsp != null ? xCsp : "",
                                xWebKit != null ? xWebKit : "",
                                parsedDirectives,
                                item.request(), resp, now
                            );
                            uniqueCSP.put(dedupeKey, cspEntry);
                        }

                        // HSTS Entry
                        if (!uniqueHSTS.containsKey(dedupeKey)) {
                            String rawHsts = resp.headerValue("Strict-Transport-Security");
                            HSTSParser.ParsedHSTS parsedHsts = HSTSParser.parse(rawHsts);

                            HSTSEntry hstsEntry = new HSTSEntry(
                                hstsDataStore.nextId(), url, host, path, method,
                                resp.statusCode(),
                                resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "",
                                rawHsts != null ? rawHsts : "",
                                parsedHsts.maxAge(),
                                parsedHsts.includeSubDomains(),
                                parsedHsts.preload(),
                                item.request(), resp, now
                            );
                            uniqueHSTS.put(dedupeKey, hstsEntry);
                        }
                    }
                }

                return new IngestionResult(
                    new ArrayList<>(uniqueCache.values()),
                    new ArrayList<>(uniqueCSP.values()),
                    new ArrayList<>(uniqueHSTS.values()),
                    processed,
                    skipped
                );
            }

            @Override
            protected void done() {
                try {
                    IngestionResult result = get();
                    cacheDataStore.addEntries(result.cacheEntries());
                    cspDataStore.addEntries(result.cspEntries());
                    hstsDataStore.addEntries(result.hstsEntries());

                    refreshAllTabs();

                    String statusMsg = "Loaded " + result.processedCount() + " messages into all inspectors.";
                    if (inScopeOnly && result.skippedCount() > 0) {
                        statusMsg += " (Skipped " + result.skippedCount() + " out-of-scope items)";
                    }

                    JOptionPane.showMessageDialog(
                        headerCollectorTab,
                        statusMsg + "\n\n"
                            + "• Header Collector: " + headerCollectorDataStore.totalUniqueValuesCount() + " unique values across " + headerCollectorDataStore.totalDomainsCount() + " domains\n"
                            + "• Method Collector: " + methodCollectorDataStore.totalMethodsCount() + " HTTP methods (" + methodCollectorDataStore.totalRequestsCount() + " requests across " + methodCollectorDataStore.totalDomainsCount() + " domains)\n"
                            + "• Status Collector: " + statusCollectorDataStore.totalStatusCodesCount() + " status codes (" + statusCollectorDataStore.totalResponsesCount() + " responses across " + statusCollectorDataStore.totalDomainsCount() + " domains)\n"
                            + "• Cache Inspector: " + cacheDataStore.size() + " unique endpoints\n"
                            + "• CSP Inspector: " + cspDataStore.size() + " unique endpoints\n"
                            + "• HSTS Inspector: " + hstsDataStore.size() + " unique endpoints",
                        "Proxy History Ingested (All Tabs)",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    api.logging().logToError("Error ingesting proxy history: " + ex.getMessage());
                } finally {
                    isLoading.set(false);
                    setAllTabsLoading(false, "");
                }
            }
        };

        worker.execute();
    }

    private void setAllTabsLoading(boolean loading, String msg) {
        if (headerCollectorTab != null) headerCollectorTab.setLoading(loading, msg);
        if (methodCollectorTab != null) methodCollectorTab.setLoading(loading, msg);
        if (statusCollectorTab != null) statusCollectorTab.setLoading(loading, msg);
        if (cacheInspectorTab != null) cacheInspectorTab.setLoading(loading, msg);
        if (cspInspectorTab != null) cspInspectorTab.setLoading(loading, msg);
        if (hstsInspectorTab != null) hstsInspectorTab.setLoading(loading, msg);
    }

    private void refreshAllTabs() {
        if (headerCollectorTab != null) headerCollectorTab.refreshView();
        if (methodCollectorTab != null) methodCollectorTab.refreshView();
        if (statusCollectorTab != null) statusCollectorTab.refreshView();
        if (cacheInspectorTab != null) cacheInspectorTab.refreshView();
        if (cspInspectorTab != null) cspInspectorTab.refreshView();
        if (hstsInspectorTab != null) hstsInspectorTab.refreshView();
    }
}
