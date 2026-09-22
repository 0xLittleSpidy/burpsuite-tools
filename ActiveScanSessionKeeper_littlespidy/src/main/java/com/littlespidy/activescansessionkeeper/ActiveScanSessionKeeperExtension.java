// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.context.SessionKeeperContextMenuProvider;
import com.littlespidy.activescansessionkeeper.engine.ActiveScanHttpHandler;
import com.littlespidy.activescansessionkeeper.engine.ExpirationDetector;
import com.littlespidy.activescansessionkeeper.engine.ScanSessionCoordinator;
import com.littlespidy.activescansessionkeeper.model.ScanActivityDataStore;
import com.littlespidy.activescansessionkeeper.ui.ActiveScanSessionKeeperTab;

/**
 * Main extension entry point implementing BurpExtension for Active Scan Session Keeper.
 * Monitors Burp Active Scanner traffic, detects session expiration across multi-factor criteria,
 * pauses scan worker threads, prompts the user with an interactive modal dialog for fresh cookies,
 * and seamlessly resumes scanning with automated request retries.
 *
 * @author littlespidy
 */
public class ActiveScanSessionKeeperExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Active Scan Session Keeper (littlespidy)");

        // 1. Initialize core configuration and datastore
        SessionKeeperConfig config = new SessionKeeperConfig();
        ScanActivityDataStore dataStore = new ScanActivityDataStore();

        // 2. Initialize coordinator & detector engines
        ScanSessionCoordinator coordinator = new ScanSessionCoordinator(api, config, dataStore);
        ExpirationDetector detector = new ExpirationDetector(config);

        // 3. Register HTTP Handler to intercept Scanner requests & responses
        ActiveScanHttpHandler httpHandler = new ActiveScanHttpHandler(api, config, coordinator, detector, dataStore);
        api.http().registerHttpHandler(httpHandler);

        // 4. Create and register Suite Tab UI
        ActiveScanSessionKeeperTab mainTab = new ActiveScanSessionKeeperTab(api, config, coordinator, dataStore);
        api.userInterface().registerSuiteTab("Session Keeper", mainTab);

        // 5. Register Context Menu Provider
        SessionKeeperContextMenuProvider contextMenu = new SessionKeeperContextMenuProvider(api, config, coordinator, mainTab);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // 6. Register Unload Handler
        api.extension().registerUnloadingHandler(() -> {
            // Unpause any blocked threads to prevent scanner lockup on unload
            coordinator.resumeScan();
            api.logging().logToOutput("Active Scan Session Keeper (littlespidy) unloaded successfully.");
        });

        api.logging().logToOutput("===============================================================");
        api.logging().logToOutput("🍪 Active Scan Session Keeper (littlespidy) loaded successfully!");
        api.logging().logToOutput("---------------------------------------------------------------");
        api.logging().logToOutput("• Monitoring: Burp Active Scanner traffic");
        api.logging().logToOutput("• Status: Active");
        api.logging().logToOutput("• Tab: 'Session Keeper' added to top suite bar");
        api.logging().logToOutput("• Context Menu: Right-click any request to set session cookies");
        api.logging().logToOutput("===============================================================");
    }
}
