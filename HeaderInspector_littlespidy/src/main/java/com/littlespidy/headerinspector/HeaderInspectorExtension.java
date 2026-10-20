// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.headerinspector.storage.HeaderPersistentStorageManager_littlespidy;

import javax.swing.SwingUtilities;

/**
 * Main extension entry point implementing BurpExtension for Header Inspector.
 * Unifies Header Collector, Method Collector, Status Collector, Cache Inspector,
 * CSP Inspector, and HSTS Inspector into a single suite tab with synchronized
 * on-demand Proxy history ingestion and persistent session management.
 *
 * @author littlespidy
 */
public class HeaderInspectorExtension implements BurpExtension {

    private HeaderPersistentStorageManager_littlespidy storageManager;
    private HeaderInspectorRootTab rootTab;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Header Inspector (littlespidy)");

        this.storageManager = new HeaderPersistentStorageManager_littlespidy(api);
        this.rootTab = new HeaderInspectorRootTab(api, storageManager);

        SwingUtilities.invokeLater(() -> {
            api.userInterface().registerSuiteTab("Header Inspector", rootTab);
            storageManager.initializeSessionOnStartup(rootTab, rootTab::refreshAllTabs);
        });

        api.extension().registerUnloadingHandler(() -> {
            if (rootTab != null) {
                rootTab.cleanup();
            }
            if (storageManager != null) {
                storageManager.shutdown();
            }
            api.logging().logToOutput("Header Inspector (littlespidy) extension unloaded successfully. State persisted if bound.");
        });

        api.logging().logToOutput("Header Inspector (littlespidy) loaded successfully! Click 'Load Proxy History' in any tab to ingest traffic across all inspectors.");
    }
}
