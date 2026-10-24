// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.wordpressinspector.engine.WordPressPassiveHandler_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressDataStore_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressTarget_littlespidy;
import com.littlespidy.wordpressinspector.storage.WordPressPreferencesManager_littlespidy;
import com.littlespidy.wordpressinspector.ui.WordPressInspectorSuiteTab_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point implementing BurpExtension for WordPress Inspector.
 * Provides passive & active WordPress auditing, WPScan API database integration,
 * core, plugin, and theme vulnerability analysis, user enumeration, and XML-RPC / REST inspection.
 *
 * @author littlespidy
 */
public class WordPressInspectorExtension_littlespidy implements BurpExtension {

    private MontoyaApi api;
    private WordPressDataStore_littlespidy dataStore;
    private WordPressPreferencesManager_littlespidy prefsManager;
    private WordPressInspectorSuiteTab_littlespidy suiteTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("WordPress Inspector (littlespidy)");

        // 1. Storage & Data Store
        this.dataStore = new WordPressDataStore_littlespidy();
        this.prefsManager = new WordPressPreferencesManager_littlespidy(api);
        this.prefsManager.loadPreferences(dataStore.getConfig());

        // 2. User Interface Suite Tab
        this.suiteTab = new WordPressInspectorSuiteTab_littlespidy(api, dataStore, prefsManager);
        SwingUtilities.invokeLater(() -> {
            api.userInterface().registerSuiteTab("WordPress Inspector", suiteTab);
        });

        // 3. Register Passive Proxy Listener
        api.proxy().registerResponseHandler(new WordPressPassiveHandler_littlespidy(dataStore));

        // 4. Register Context Menu Item
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> items = new ArrayList<>();
                JMenuItem sendItem = new JMenuItem("Send to WordPress Inspector");
                sendItem.addActionListener(e -> handleSendToInspector(event));
                items.add(sendItem);
                return items;
            }
        });

        // 5. Register Unloading Handler
        api.extension().registerUnloadingHandler(() -> {
            if (prefsManager != null && dataStore != null) {
                prefsManager.savePreferences(dataStore.getConfig());
            }
            api.logging().logToOutput("WordPress Inspector (littlespidy) unloaded successfully.");
        });

        api.logging().logToOutput("WordPress Inspector (littlespidy) loaded successfully.");
    }

    private void handleSendToInspector(ContextMenuEvent event) {
        String url = null;
        String host = null;

        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse rr = event.messageEditorRequestResponse().get().requestResponse();
            url = rr.request().url();
            host = rr.request().httpService().host();
        } else if (!event.selectedRequestResponses().isEmpty()) {
            HttpRequestResponse rr = event.selectedRequestResponses().get(0);
            url = rr.request().url();
            host = rr.request().httpService().host();
        }

        if (url != null && host != null) {
            WordPressTarget_littlespidy target = dataStore.getOrCreateTarget(url, host);
            SwingUtilities.invokeLater(() -> suiteTab.openDomainTab(target));
        }
    }
}
