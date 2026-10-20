// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.ssoinspector.context.SSOContextMenuProvider;
import com.littlespidy.ssoinspector.engine.OAuthActiveScanEngine;
import com.littlespidy.ssoinspector.engine.SSOScanCheck;
import com.littlespidy.ssoinspector.model.OAuthDataStore;
import com.littlespidy.ssoinspector.storage.SSOPersistentStorageManager_littlespidy;
import com.littlespidy.ssoinspector.ui.SSOMainSuiteTab;

import javax.swing.*;

public class SSOInspectorExtension implements BurpExtension {

    private MontoyaApi api;
    private OAuthDataStore dataStore;
    private OAuthActiveScanEngine activeScanEngine;
    private SSOMainSuiteTab mainSuiteTab;
    private SSOPersistentStorageManager_littlespidy storageManager;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // 1. Set Extension Name
        api.extension().setName("SSO Inspector (littlespidy)");

        // 2. Initialize Data Store & Active Scan Engine
        this.dataStore = new OAuthDataStore();
        this.activeScanEngine = new OAuthActiveScanEngine(api);

        // 3. Initialize Storage Manager & Main Suite UI Tab
        this.storageManager = new SSOPersistentStorageManager_littlespidy(api);
        this.storageManager.bindDataStore(dataStore);

        this.mainSuiteTab = new SSOMainSuiteTab(api, dataStore, activeScanEngine, storageManager);
        SwingUtilities.invokeLater(() -> {
            api.userInterface().registerSuiteTab("SSO Inspector", mainSuiteTab);
            storageManager.initializeSessionOnStartup(mainSuiteTab, () -> mainSuiteTab.getOAuthTab().onStoreCleared());
        });

        // 4. Register Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(
                new SSOContextMenuProvider(api, dataStore, mainSuiteTab)
        );

        // 5. Register Scanner Check (Passive & Active)
        api.scanner().registerScanCheck(new SSOScanCheck(api, activeScanEngine));

        // 6. Register Unloading Handler
        api.extension().registerUnloadingHandler(() -> {
            if (storageManager != null) {
                storageManager.shutdown();
            }
            api.logging().logToOutput("[SSO Inspector] Extension unloaded cleanly.");
        });

        // 7. Startup Log
        api.logging().logToOutput("[SSO Inspector (littlespidy)] Loaded successfully.");
        api.logging().logToOutput("[SSO Inspector] Suite tab 'SSO Inspector' and sub-tab 'OAuth' are active.");
    }
}
