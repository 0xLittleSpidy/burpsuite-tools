// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.jwtcomparator.context.JWTContextMenuProvider;
import com.littlespidy.jwtcomparator.ui.JWTComparatorTab;

/**
 * Main Burp Suite extension entry point for JWT Comparator.
 */
public class JWTComparatorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        // 1. Set Extension Name
        api.extension().setName("JWT Comparator (littlespidy)");

        // 2. Initialize Main UI Tab
        JWTComparatorTab mainTab = new JWTComparatorTab(api);
        api.userInterface().registerSuiteTab("JWT Comparator", mainTab);

        // 3. Register Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(new JWTContextMenuProvider(api, mainTab));

        // 4. Register Unloading Handler
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("JWT Comparator extension unloaded.");
        });

        api.logging().logToOutput("JWT Comparator extension loaded successfully!");
        api.logging().logToOutput("Use the 'JWT Comparator' suite tab or right-click 'Send to JWT Comparator' from any HTTP request/response.");
    }
}
