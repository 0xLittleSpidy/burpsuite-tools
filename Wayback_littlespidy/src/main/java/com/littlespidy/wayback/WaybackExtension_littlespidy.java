// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.wayback.menu.WaybackContextMenu_littlespidy;
import com.littlespidy.wayback.ui.WaybackTab_littlespidy;

import javax.swing.*;

public class WaybackExtension_littlespidy implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("wayback");

        api.logging().logToOutput("=================================================");
        api.logging().logToOutput("wayback v2.0 - Burp Suite Extension (by FR13ND0x7F & littlespidy)");
        api.logging().logToOutput("Wayback Machine Directory Reconnaissance & Probing");
        api.logging().logToOutput("Dedicated Multi-Domain Tab Model & Persistent Session Storage");
        api.logging().logToOutput("=================================================");

        WaybackTab_littlespidy mainTab = new WaybackTab_littlespidy(api);

        api.userInterface().registerSuiteTab("wayback", mainTab);
        api.userInterface().registerContextMenuItemsProvider(new WaybackContextMenu_littlespidy(mainTab));

        SwingUtilities.invokeLater(mainTab::initializeSessionStartup);
    }
}
