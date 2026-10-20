// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.payloadinjector.model.InjectionSettings;
import com.littlespidy.payloadinjector.model.ParamPayloadStore;
import com.littlespidy.payloadinjector.model.PayloadCategoryRegistry_littlespidy;
import com.littlespidy.payloadinjector.model.SmugglingPayloadStore;
import com.littlespidy.payloadinjector.storage.PayloadInjectorPersistentStorageManager_littlespidy;
import com.littlespidy.payloadinjector.ui.PayloadContextMenuProvider;
import com.littlespidy.payloadinjector.ui.PayloadInjectorTab;

import javax.swing.*;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point for Payload Injector.
 * Initializes dedicated tabs for all JSON payload files (wrapping across multiple rows),
 * persistent session management, and provides full context menu integration for all categories.
 * Plain ASCII text only.
 *
 * @author littlespidy
 */
public class PayloadInjectorExtension implements BurpExtension {

    private PayloadInjectorPersistentStorageManager_littlespidy storageManager;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Payload Injector (littlespidy)");

        // -- 1. Initialize Stores & Settings --
        Map<String, ParamPayloadStore> paramStores = PayloadCategoryRegistry_littlespidy.createAllParamStores(api);
        SmugglingPayloadStore smugglingStore = new SmugglingPayloadStore(api);
        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy linuxFilePathStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(api, "linux_file_paths_littlespidy.json", "Linux");
        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy windowsFilePathStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(api, "windows_file_paths_littlespidy.json", "Windows");
        InjectionSettings settings = new InjectionSettings();

        // -- 2. Register Master Suite Tab with Storage Manager --
        PayloadInjectorTab masterTab = new PayloadInjectorTab(
                paramStores,
                smugglingStore,
                linuxFilePathStore,
                windowsFilePathStore,
                settings
        );
        this.storageManager = new PayloadInjectorPersistentStorageManager_littlespidy(api);
        this.storageManager.bindContext(masterTab, paramStores, smugglingStore, linuxFilePathStore, windowsFilePathStore, settings);
        masterTab.setStorageManager(storageManager);

        api.userInterface().registerSuiteTab("Payload Injector", masterTab);

        // -- 3. Initialize Session via Startup Dialog --
        SwingUtilities.invokeLater(() -> {
            storageManager.initializeSessionOnStartup(masterTab, () -> masterTab.revalidate());
        });

        // -- 4. Register Context Menu Provider --
        api.userInterface().registerContextMenuItemsProvider(
                new PayloadContextMenuProvider(
                        api,
                        paramStores,
                        smugglingStore,
                        linuxFilePathStore,
                        windowsFilePathStore,
                        settings
                )
        );

        // -- 5. Register Unloading Handler --
        api.extension().registerUnloadingHandler(() -> {
            if (storageManager != null) {
                storageManager.shutdown();
            }
            api.logging().logToOutput("Payload Injector extension unloaded successfully.");
        });

        api.logging().logToOutput("Payload Injector (littlespidy) loaded successfully!");
    }
}
