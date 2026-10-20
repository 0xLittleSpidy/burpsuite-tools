// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector;

import com.littlespidy.requestsmugglinginspector.model.PayloadStore;
import com.littlespidy.requestsmugglinginspector.storage.SmugglingPersistentStorageManager_littlespidy;
import com.littlespidy.requestsmugglinginspector.ui.PayloadsTab;
import com.littlespidy.requestsmugglinginspector.ui.SmugglingContextMenuProvider;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main entry point for the Request Smuggling Inspector Burp Suite extension.
 * Integrated with persistent session management.
 * Plain ASCII text only.
 *
 * @author littlespidy
 */
public class RequestSmugglingInspectorExtension implements BurpExtension {

    private SmugglingPersistentStorageManager_littlespidy storageManager;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Request Smuggling Inspector (littlespidy)");

        // 1. Load payloads from smuggling-payloads.json (sibling of the JAR)
        PayloadStore store = new PayloadStore(api);
        PayloadsTab tab = new PayloadsTab(store);

        // 2. Setup Persistent Session Manager
        this.storageManager = new SmugglingPersistentStorageManager_littlespidy(api);
        this.storageManager.bindTab(tab);
        this.storageManager.bindStore(store);
        tab.setStorageManager(storageManager);

        // 3. Register the Smuggling Payloads suite tab
        api.userInterface().registerSuiteTab(
                "Smuggling Payloads",
                tab
        );

        // 4. Initialize Session via Startup Dialog
        SwingUtilities.invokeLater(() -> {
            storageManager.initializeSessionOnStartup(tab, () -> tab.refreshTable());
        });

        // 5. Register the dynamic right-click context menu in Repeater
        api.userInterface().registerContextMenuItemsProvider(
                new SmugglingContextMenuProvider(api, store)
        );

        // 6. Unload hook
        api.extension().registerUnloadingHandler(() -> {
            if (storageManager != null) {
                storageManager.shutdown();
            }
            api.logging().logToOutput("Request Smuggling Inspector unloaded.");
        });

        api.logging().logToOutput("Request Smuggling Inspector (littlespidy) loaded!");
    }
}
