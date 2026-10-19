// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector;

import com.littlespidy.apiinspector.persistence.APIInspectorPersistenceManager_littlespidy;
import com.littlespidy.apiinspector.ui.APIInspectorContextMenu_littlespidy;
import com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;

/**
 * API Inspector Burp Suite Extension.
 * Provides the ResAPI Version Finder tab with per-request sub-tabs,
 * automated version discovery strategies, and persistent session recovery.
 */
public class APIInspectorExtension_littlespidy implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("API Inspector (littlespidy)");

        APIInspectorPersistenceManager_littlespidy persistenceManager = new APIInspectorPersistenceManager_littlespidy(api);
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(api);

        rootTab.getVersionFinderTab().setPersistenceManager(persistenceManager);

        // Register Suite Tab
        api.userInterface().registerSuiteTab("API Inspector", rootTab);

        // Register Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(
                new APIInspectorContextMenu_littlespidy(rootTab.getVersionFinderTab())
        );

        // Resolve storage directory and restore previous sessions
        SwingUtilities.invokeLater(() -> {
            persistenceManager.resolveStorageDirectory(null);
            rootTab.getVersionFinderTab().updateStorageDisplay();
            persistenceManager.loadSession(rootTab.getVersionFinderTab());
        });

        // Register clean shutdown unloading handler
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("[API Inspector] Extension unloading - saving persistent state...");
            persistenceManager.saveSync(rootTab.getVersionFinderTab());
            api.logging().logToOutput("[API Inspector] Persistent state saved successfully.");
        });

        api.logging().logToOutput("[API Inspector] Extension initialized successfully.");
        api.logging().logToOutput("[API Inspector] ResAPI Version Finder tab registered with session persistence.");
    }
}
