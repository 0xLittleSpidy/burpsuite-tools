// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector;

import com.littlespidy.cacheheaderinspector.model.CacheDataStore;
import com.littlespidy.cacheheaderinspector.ui.CacheInspectorTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point implementing BurpExtension for Cache Header Inspector.
 * Operates on-demand: loads and analyzes URLs and responses from Burp Proxy history
 * upon user request, deduplicating URLs and providing rich filtering.
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

        // ── 2. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanup();
            }
            api.logging().logToOutput("Cache Header Inspector extension unloaded successfully.");
        });

        api.logging().logToOutput("Cache Header Inspector (littlespidy) loaded successfully! Click 'Load Proxy History' in the Cache Inspector tab to ingest targets.");
    }
}

