// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.quickhelper.menu.QuickHelperContextMenu_littlespidy;
import com.littlespidy.quickhelper.menu.QuickHelperMenuBar_littlespidy;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;
import com.littlespidy.quickhelper.service.DomainExtractorService_littlespidy;

import javax.swing.JMenu;

/**
 * Entry point for Quick Helper Burp Suite Extension.
 */
public class QuickHelperExtension_littlespidy implements BurpExtension {

    private static final String EXTENSION_NAME = "Quick Helper [littlespidy]";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        ClipboardService_littlespidy clipboardService = new ClipboardService_littlespidy();
        DomainExtractorService_littlespidy extractorService = new DomainExtractorService_littlespidy(api, clipboardService);

        // Register top-level Menu Bar
        QuickHelperMenuBar_littlespidy menuBar = new QuickHelperMenuBar_littlespidy(extractorService);
        JMenu topMenu = menuBar.createMenu();
        api.userInterface().menuBar().registerMenu(topMenu);

        // Register Context Menu Provider (SiteMap, Proxy, Repeater, etc.)
        QuickHelperContextMenu_littlespidy contextMenu = new QuickHelperContextMenu_littlespidy(extractorService);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // Register clean shutdown handler
        api.extension().registerUnloadingHandler(extractorService::shutdown);

        // Log initialization
        api.logging().logToOutput("==================================================");
        api.logging().logToOutput("  " + EXTENSION_NAME + " loaded successfully");
        api.logging().logToOutput("  Menu: Registered in top Menu Bar & Context Menu");
        api.logging().logToOutput("  Actions:");
        api.logging().logToOutput("    - Copy All Domain Names");
        api.logging().logToOutput("    - Copy All Domain Names with HTTP Schema");
        api.logging().logToOutput("    - Copy In-Scope Domain Names");
        api.logging().logToOutput("    - Copy In-Scope Domain Names with HTTP Schema");
        api.logging().logToOutput("==================================================");
    }
}
