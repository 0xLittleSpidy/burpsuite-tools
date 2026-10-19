// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector;

import com.littlespidy.apiinspector.ui.APIInspectorContextMenu_littlespidy;
import com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * API Inspector Burp Suite Extension.
 * Provides the ResAPI Version Finder tab with per-request sub-tabs and
 * automated version discovery strategies (URI path, headers, query params,
 * content negotiation, subdomains, cookies).
 */
public class APIInspectorExtension_littlespidy implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("API Inspector (littlespidy)");

        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(api);

        // Register Suite Tab
        api.userInterface().registerSuiteTab("API Inspector", rootTab);

        // Register Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(
                new APIInspectorContextMenu_littlespidy(rootTab.getVersionFinderTab())
        );

        api.logging().logToOutput("[API Inspector] Extension initialized successfully.");
        api.logging().logToOutput("[API Inspector] ResAPI Version Finder tab registered.");
    }
}
