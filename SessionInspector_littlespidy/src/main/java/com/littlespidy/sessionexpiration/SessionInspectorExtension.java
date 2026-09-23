// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.sessionexpiration.context.SessionContextMenuProvider;
import com.littlespidy.sessionexpiration.engine.SessionTimerEngine;
import com.littlespidy.sessionexpiration.model.SessionDataStore;
import com.littlespidy.sessionexpiration.persistence.SessionInspectorPersistence;
import com.littlespidy.sessionexpiration.ui.SessionExpirationTab;

/**
 * Main extension entrypoint implementing BurpExtension for Session Inspector.
 *
 * Enables penetration testers and security researchers to schedule custom interval probes
 * (e.g., 30m, 1h, 3h, 8h) for authenticated requests to test idle and absolute session expiration.
 * Captures initial baseline responses with session cookies, re-probes at milestones, detects expiration
 * via status code transitions and content heuristics, and automatically cancels remaining timers on expiry.
 *
 * @author littlespidy
 */
public class SessionInspectorExtension implements BurpExtension {

    private MontoyaApi api;
    private SessionDataStore dataStore;
    private SessionTimerEngine timerEngine;
    private SessionExpirationTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // 1. Set Extension Name
        api.extension().setName("Session Inspector (littlespidy)");

        // 2. Initialize Core Engine and Store
        this.dataStore = new SessionDataStore();
        this.timerEngine = new SessionTimerEngine(api);

        // 3. Initialize Main Suite UI Tab
        this.mainTab = new SessionExpirationTab(api, dataStore, timerEngine);
        api.userInterface().registerSuiteTab("⏱️ Session Inspector", mainTab);

        // 4. Register Right-Click Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(
                new SessionContextMenuProvider(api, dataStore, timerEngine, mainTab)
        );

        // 5. Restore Persistent State (across extension reload or Burp restart)
        try {
            String restoreSummary = SessionInspectorPersistence.load(
                    dataStore, mainTab.getCookieStoreDataStore(), mainTab.getCookieFinderTab(), api
            );
            mainTab.refreshAllTabs();
            api.logging().logToOutput("[Session Inspector] " + restoreSummary);
        } catch (Exception ex) {
            api.logging().logToError("[Session Inspector] Failed to restore persistent state: " + ex.getMessage());
        }

        // 6. Register Extension Unloading Handler
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("[Session Inspector] Unloading extension: saving state & terminating timers...");
            try {
                SessionInspectorPersistence.saveSync(
                        dataStore, mainTab.getCookieStoreDataStore(), mainTab.getCookieFinderTab()
                );
                api.logging().logToOutput("[Session Inspector] Saved persistent state to disk.");
            } catch (Exception ex) {
                api.logging().logToError("[Session Inspector] Error saving persistent state on unload: " + ex.getMessage());
            }

            if (mainTab != null) {
                mainTab.cleanup();
            }
            if (timerEngine != null) {
                timerEngine.shutdown();
            }
            api.logging().logToOutput("[Session Inspector] Extension unloaded cleanly.");
        });

        api.logging().logToOutput("================================================================");
        api.logging().logToOutput("⏱️ Session Inspector (littlespidy) loaded successfully!");
        api.logging().logToOutput("Right-click any authenticated request -> '⏱️ Send to Session Inspector'");
        api.logging().logToOutput("Configure custom milestones (e.g., 30m, 1h, 3h, 8h) and track expiration.");
        api.logging().logToOutput("================================================================");
    }
}
