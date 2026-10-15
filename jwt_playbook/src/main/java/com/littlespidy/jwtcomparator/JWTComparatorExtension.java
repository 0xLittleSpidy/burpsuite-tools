// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.jwtcomparator.context.JWTContextMenuProvider;
import com.littlespidy.jwtcomparator.ui.JWTComparatorTab;

/**
 * Main Burp Suite extension entry point for jwt_playbook.
 */
public class JWTComparatorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        // 1. Set Extension Name
        api.extension().setName("jwt_playbook");

        // 2. Initialize Main UI Tab
        JWTComparatorTab mainTab = new JWTComparatorTab(api);
        api.userInterface().registerSuiteTab("jwt_playbook", mainTab);

        // 3. Register Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(new JWTContextMenuProvider(api, mainTab));

        // 4. Register Unloading Handler
        api.extension().registerUnloadingHandler(() -> {
            mainTab.close();
            api.logging().logToOutput("jwt_playbook extension unloaded.");
        });

        api.logging().logToOutput("jwt_playbook extension loaded successfully!");
        api.logging().logToOutput("Use Offline Analysis or Attack, or right-click a request to send it to JWT analysis.");
    }
}
