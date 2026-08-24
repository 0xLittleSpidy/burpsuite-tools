// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector;

import com.littlespidy.cacheheaderinspector.model.CacheDataStore;
import com.littlespidy.cacheheaderinspector.model.CacheEntry;
import com.littlespidy.cacheheaderinspector.ui.CacheInspectorTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import java.time.ZonedDateTime;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point implementing BurpExtension for Cache Header Inspector.
 * Passively captures all HTTP responses and organizes caching behavior by directives and URLs.
 *
 * @author littlespidy
 */
public class CacheHeaderInspectorExtension implements BurpExtension {

    private MontoyaApi api;
    private final CacheDataStore dataStore = new CacheDataStore();
    private CacheInspectorTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Cache Header Inspector (littlespidy)");

        // ── 1. Create and Register Suite Tab ──
        this.mainTab = new CacheInspectorTab(api, dataStore);
        api.userInterface().registerSuiteTab("Cache Inspector", mainTab);

        // ── 2. Register Passive HTTP Handler ──
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
                return RequestToBeSentAction.continueWith(httpRequestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
                try {
                    var req = httpResponseReceived.initiatingRequest();
                    String url = req.url();
                    String host = req.httpService() != null ? req.httpService().host() : "";
                    String path = req.path() != null ? req.path() : "/";

                    CacheEntry entry = new CacheEntry(
                        dataStore.nextId(),
                        url,
                        host,
                        path,
                        httpResponseReceived.statusCode(),
                        httpResponseReceived.headerValue("Content-Type") != null ? httpResponseReceived.headerValue("Content-Type") : "",
                        httpResponseReceived.headerValue("Cache-Control") != null ? httpResponseReceived.headerValue("Cache-Control") : "",
                        httpResponseReceived.headerValue("Pragma") != null ? httpResponseReceived.headerValue("Pragma") : "",
                        httpResponseReceived.headerValue("Expires") != null ? httpResponseReceived.headerValue("Expires") : "",
                        httpResponseReceived.headerValue("Age") != null ? httpResponseReceived.headerValue("Age") : "",
                        httpResponseReceived.headerValue("ETag") != null ? httpResponseReceived.headerValue("ETag") : "",
                        httpResponseReceived.headerValue("Last-Modified") != null ? httpResponseReceived.headerValue("Last-Modified") : "",
                        httpResponseReceived.headerValue("Vary") != null ? httpResponseReceived.headerValue("Vary") : "",
                        httpResponseReceived.headerValue("X-Cache") != null ? httpResponseReceived.headerValue("X-Cache") : "",
                        httpResponseReceived.headerValue("X-Cache-Hits") != null ? httpResponseReceived.headerValue("X-Cache-Hits") : "",
                        httpResponseReceived.headerValue("CDN-Cache-Control") != null ? httpResponseReceived.headerValue("CDN-Cache-Control") : "",
                        httpResponseReceived.headerValue("Surrogate-Control") != null ? httpResponseReceived.headerValue("Surrogate-Control") : "",
                        httpResponseReceived.headerValue("CF-Cache-Status") != null ? httpResponseReceived.headerValue("CF-Cache-Status") : "",
                        req,
                        httpResponseReceived,
                        ZonedDateTime.now()
                    );

                    dataStore.addEntry(entry);
                } catch (Exception ex) {
                    api.logging().logToError("Error processing response in CacheHeaderInspector: " + ex.getMessage());
                }

                return ResponseReceivedAction.continueWith(httpResponseReceived);
            }
        });

        // ── 3. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanup();
            }
            api.logging().logToOutput("Cache Header Inspector extension unloaded successfully.");
        });

        api.logging().logToOutput("Cache Header Inspector (littlespidy) loaded successfully!");
    }
}
