// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.hstsinspector.model.HSTSDataStore;
import com.littlespidy.hstsinspector.storage.HSTSPersistentStorageManager_littlespidy;
import com.littlespidy.hstsinspector.ui.HSTSInspectorTab;

import javax.swing.*;

/**
 * Entry point for the HSTS Inspector Burp Suite extension.
 * Registers the extension, installs session persistence, and creates the custom UI tab.
 *
 * @author littlespidy
 */
public class HSTSInspectorExtension implements BurpExtension {

    private HSTSInspectorTab inspectorTab;
    private HSTSPersistentStorageManager_littlespidy storageManager;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("HSTS Inspector");

        HSTSDataStore dataStore = new HSTSDataStore();
        storageManager = new HSTSPersistentStorageManager_littlespidy(api);
        storageManager.bindDataStore(dataStore);

        inspectorTab = new HSTSInspectorTab(api, dataStore, storageManager);

        SwingUtilities.invokeLater(() -> {
            api.userInterface().registerSuiteTab("HSTS Inspector", inspectorTab);
            storageManager.initializeSessionOnStartup(inspectorTab, inspectorTab::refreshView);
        });

        api.extension().registerUnloadingHandler(() -> {
            if (inspectorTab != null) inspectorTab.cleanup();
            if (storageManager != null) storageManager.shutdown();
        });

        api.logging().logToOutput("HSTS Inspector loaded successfully.");
    }
}
