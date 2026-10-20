// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector;

import com.littlespidy.cspinspector.model.CSPDataStore;
import com.littlespidy.cspinspector.storage.CSPPersistentStorageManager_littlespidy;
import com.littlespidy.cspinspector.ui.CSPInspectorTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.SwingUtilities;

/**
 * Main extension entry point implementing BurpExtension for CSP Inspector.
 * Operates on-demand: loads, parses, and audits Content Security Policies from Burp Proxy history,
 * deduplicating endpoints and offering multi-level directive analysis and fast triage filtering.
 *
 * @author littlespidy
 */
public class CSPInspectorExtension implements BurpExtension {

    private MontoyaApi api;
    private final CSPDataStore dataStore = new CSPDataStore();
    private CSPPersistentStorageManager_littlespidy storageManager;
    private CSPInspectorTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("CSP Inspector (littlespidy)");

        // ── 1. Create and Register Storage Manager & Suite Tab ──
        this.storageManager = new CSPPersistentStorageManager_littlespidy(api);
        this.storageManager.bindDataStore(dataStore);

        this.mainTab = new CSPInspectorTab(api, dataStore, storageManager);
        api.userInterface().registerSuiteTab("CSP Inspector", mainTab);

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
            api.logging().logToOutput("CSP Inspector extension unloaded successfully. State persisted if bound.");
        });

        api.logging().logToOutput("CSP Inspector (littlespidy) loaded successfully! Click 'Load Proxy History' in the CSP Inspector tab to ingest targets.");
    }
}
