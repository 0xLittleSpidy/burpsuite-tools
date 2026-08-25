// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.cspinspector;

import com.littlespidy.cspinspector.model.CSPDataStore;
import com.littlespidy.cspinspector.ui.CSPInspectorTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point implementing BurpExtension for CSP Inspector.
 * Operates on-demand: loads, parses, and audits Content Security Policies from Burp Proxy history,
 * deduplicating endpoints and offering multi-level directive analysis and fast triage filtering.
 *
 * @author littlespidy
 */
public class CSPInspectorExtension implements BurpExtension {

    private MontoyaApi api;
    private final CSPDataStore dataStore = new CSPDataStore();
    private CSPInspectorTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("CSP Inspector (littlespidy)");

        // ── 1. Create and Register Suite Tab ──
        this.mainTab = new CSPInspectorTab(api, dataStore);
        api.userInterface().registerSuiteTab("CSP Inspector", mainTab);

        // ── 2. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanup();
            }
            api.logging().logToOutput("CSP Inspector extension unloaded successfully.");
        });

        api.logging().logToOutput("CSP Inspector (littlespidy) loaded successfully! Click 'Load Proxy History' in the CSP Inspector tab to ingest targets.");
    }
}
