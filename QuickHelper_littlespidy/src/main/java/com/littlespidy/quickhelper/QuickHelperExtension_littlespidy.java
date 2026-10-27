// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.quickhelper.editor.AuthHttpRequestEditorProvider_littlespidy;
import com.littlespidy.quickhelper.editor.JsonTableResponseEditorProvider_littlespidy;
import com.littlespidy.quickhelper.menu.QuickHelperContextMenu_littlespidy;
import com.littlespidy.quickhelper.menu.QuickHelperMenuBar_littlespidy;
import com.littlespidy.quickhelper.service.AuthTokenExtractorService_littlespidy;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;
import com.littlespidy.quickhelper.service.DomainExtractorService_littlespidy;
import com.littlespidy.quickhelper.service.ExtensionCatalogService_littlespidy;
import com.littlespidy.quickhelper.service.ExtensionDownloaderService_littlespidy;
import com.littlespidy.quickhelper.service.JsonTableService_littlespidy;
import com.littlespidy.quickhelper.ui.QuickHelperRootTab_littlespidy;

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
        ExtensionCatalogService_littlespidy catalogService = new ExtensionCatalogService_littlespidy();
        ExtensionDownloaderService_littlespidy downloaderService = new ExtensionDownloaderService_littlespidy(api);
        AuthTokenExtractorService_littlespidy authExtractorService = new AuthTokenExtractorService_littlespidy();
        JsonTableService_littlespidy jsonService = new JsonTableService_littlespidy();

        // Register Request Editor Tab: Copy
        AuthHttpRequestEditorProvider_littlespidy authEditorProvider = new AuthHttpRequestEditorProvider_littlespidy(
                api,
                clipboardService,
                authExtractorService
        );
        api.userInterface().registerHttpRequestEditorProvider(authEditorProvider);

        // Register Response Editor Tab: JSON Table
        JsonTableResponseEditorProvider_littlespidy jsonEditorProvider = new JsonTableResponseEditorProvider_littlespidy(
                api,
                clipboardService,
                jsonService
        );
        api.userInterface().registerHttpResponseEditorProvider(jsonEditorProvider);

        // Register Suite Tab: Quick Helper (Extensions Downloader + Domain Extractor)
        QuickHelperRootTab_littlespidy rootTab = new QuickHelperRootTab_littlespidy(
                api,
                catalogService,
                downloaderService,
                extractorService,
                clipboardService
        );
        api.userInterface().registerSuiteTab("Quick Helper", rootTab);

        // Register top-level Menu Bar
        QuickHelperMenuBar_littlespidy menuBar = new QuickHelperMenuBar_littlespidy(extractorService, rootTab);
        JMenu topMenu = menuBar.createMenu();
        api.userInterface().menuBar().registerMenu(topMenu);

        // Register Context Menu Provider (SiteMap, Proxy, Repeater, etc.)
        QuickHelperContextMenu_littlespidy contextMenu = new QuickHelperContextMenu_littlespidy(extractorService, rootTab);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // Register clean shutdown handler
        api.extension().registerUnloadingHandler(() -> {
            extractorService.shutdown();
            downloaderService.shutdown();
        });

        // Log initialization
        api.logging().logToOutput("==================================================");
        api.logging().logToOutput("  " + EXTENSION_NAME + " loaded successfully");
        api.logging().logToOutput("  Suite Tab: 'Quick Helper' registered");
        api.logging().logToOutput("  Request Editor Tab: 'Copy' registered");
        api.logging().logToOutput("  Response Editor Tab: 'JSON Table' registered");
        api.logging().logToOutput("  Menu: Registered in top Menu Bar and Context Menu");
        api.logging().logToOutput("  Features:");
        api.logging().logToOutput("    - Request Editor Tab ('Copy'): One-Click Copy for Bearer, Auth Header, Cookies");
        api.logging().logToOutput("    - Response Editor Tab ('JSON Table'): JSON to Table Converter with Live Filter and CSV Export");
        api.logging().logToOutput("    - Single-Click Extension Downloader (" + catalogService.getExtensionCount() + " extensions)");
        api.logging().logToOutput("    - Copy All Domain Names");
        api.logging().logToOutput("    - Copy All Domain Names with HTTP Schema");
        api.logging().logToOutput("    - Copy In-Scope Domain Names");
        api.logging().logToOutput("    - Copy In-Scope Domain Names with HTTP Schema");
        api.logging().logToOutput("==================================================");
    }
}
