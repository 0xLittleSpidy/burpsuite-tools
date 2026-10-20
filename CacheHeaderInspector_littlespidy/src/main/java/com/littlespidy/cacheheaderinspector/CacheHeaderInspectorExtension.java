// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cacheheaderinspector;

import com.littlespidy.cacheheaderinspector.model.CacheDataStore;
import com.littlespidy.cacheheaderinspector.storage.CachePersistentStorageManager_littlespidy;
import com.littlespidy.cacheheaderinspector.ui.CacheInspectorTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.SwingUtilities;

/**
 * Main extension entry point implementing BurpExtension for Cache Header Inspector.
 * Operates on-demand: loads and analyzes URLs and responses from Burp Proxy history
 * upon user request, deduplicating URLs and providing rich filtering.
 *
 * @author littlespidy
 */
public class CacheHeaderInspectorExtension implements BurpExtension {

    private MontoyaApi api;
    private final CacheDataStore dataStore = new CacheDataStore();
    private CachePersistentStorageManager_littlespidy storageManager;
    private CacheInspectorTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Cache Header Inspector (littlespidy)");

        // ── 1. Initialize Storage Manager & UI Tab ──
        this.storageManager = new CachePersistentStorageManager_littlespidy(api);
        this.storageManager.bindDataStore(dataStore);

        this.mainTab = new CacheInspectorTab(api, dataStore, storageManager);
        api.userInterface().registerSuiteTab("Cache Inspector", mainTab);

        // ── 2. Interactive Startup Prompt (Never auto-load silently) ──
        SwingUtilities.invokeLater(() -> storageManager.initializeSessionOnStartup(mainTab, mainTab::refreshView));

        // ── 3. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanup();
            }
            if (storageManager != null) {
                storageManager.shutdown();
            }
            api.logging().logToOutput("Cache Header Inspector extension unloaded successfully. State persisted if bound.");
        });

        api.logging().logToOutput("Cache Header Inspector (littlespidy) loaded successfully! Click 'Load Proxy History' in the Cache Inspector tab to ingest targets.");
    }
}
