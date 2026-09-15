// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point implementing BurpExtension for Header Inspector.
 * Unifies Header Collector, Cache Inspector, CSP Inspector, and HSTS Inspector
 * into a single suite tab with synchronized on-demand Proxy history ingestion.
 *
 * @author littlespidy
 */
public class HeaderInspectorExtension implements BurpExtension {

    private HeaderInspectorRootTab rootTab;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Header Inspector (littlespidy)");

        this.rootTab = new HeaderInspectorRootTab(api);

        SwingUtilities.invokeLater(() ->
            api.userInterface().registerSuiteTab("📋 Header Inspector", rootTab)
        );

        api.extension().registerUnloadingHandler(() -> {
            if (rootTab != null) {
                rootTab.cleanup();
            }
            api.logging().logToOutput("Header Inspector (littlespidy) extension unloaded successfully.");
        });

        api.logging().logToOutput("Header Inspector (littlespidy) loaded successfully! Click 'Load Proxy History' in any tab to ingest traffic across all inspectors.");
    }
}
