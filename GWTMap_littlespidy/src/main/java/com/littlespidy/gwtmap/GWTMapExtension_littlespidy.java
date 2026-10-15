// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.gwtmap.engine.GWTScanEngine;
import com.littlespidy.gwtmap.model.GWTDataStore;
import com.littlespidy.gwtmap.ui.GWTMapTab;
import com.littlespidy.gwtmap.ui.editor.GwtHttpRequestEditorProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Main Montoya extension entrypoint for GWTMap.
 *
 * @author littlespidy
 */
public class GWTMapExtension_littlespidy implements BurpExtension {

    private MontoyaApi api;
    private GWTDataStore dataStore;
    private GWTScanEngine scanEngine;
    private GWTMapTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("GWTMap - GWT RPC Analyzer [littlespidy]");

        api.logging().logToOutput("Created with the help of an AI Agent and littlespidy.");
        api.logging().logToOutput("[+] GWTMap v1.0.0 (Montoya API) initialized.");
        api.logging().logToOutput("[+] Fully ports and enhances https://github.com/reverseclabs/gwtmap into Burp Suite.");
        api.logging().logToOutput("[+] Integrated GWT Deserializer, Fuzzer, and Native Editor Tab (GWTab & GWT-Penetration-Testing-Toolset).");

        this.dataStore = new GWTDataStore();
        this.scanEngine = new GWTScanEngine(api, dataStore);
        this.mainTab = new GWTMapTab(api, dataStore, scanEngine);

        // Load persisted session if available
        SwingUtilities.invokeLater(() -> {
            try {
                mainTab.loadSavedSession();
            } catch (Exception e) {
                api.logging().logToError("[GWTMap] Error loading saved session: " + e.getMessage());
            }
        });

        // 1. Register Suite Tab
        api.userInterface().registerSuiteTab("GWTMap", mainTab);

        // 2. Register Native HTTP Request Editor Provider ("GWT" Tab in Proxy / Repeater)
        api.userInterface().registerHttpRequestEditorProvider(new GwtHttpRequestEditorProvider(api, mainTab));

        // 3. Register Context Menus: "Send to GWTMap", "Send to GWTMap Deserializer", "Send to GWTMap Fuzzer"
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuItems = new ArrayList<>();

                HttpRequestResponse targetItem = null;
                if (event.messageEditorRequestResponse().isPresent()) {
                    targetItem = event.messageEditorRequestResponse().get().requestResponse();
                } else if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
                    targetItem = event.selectedRequestResponses().get(0);
                }

                final HttpRequestResponse resolvedItem = targetItem;

                JMenuItem scanItem = new JMenuItem("Send to GWTMap (Scan / Enumerate)");
                scanItem.addActionListener(e -> {
                    if (resolvedItem != null && resolvedItem.request() != null) {
                        String url = resolvedItem.request().url();
                        mainTab.setTargetUrl(url);
                        mainTab.startAnalysis();
                        api.logging().logToOutput("[GWTMap] Dispatched analysis for: " + url);
                    }
                });
                menuItems.add(scanItem);

                JMenuItem deserItem = new JMenuItem("Send to GWTMap Deserializer");
                deserItem.addActionListener(e -> {
                    if (resolvedItem != null && resolvedItem.request() != null) {
                        String body = resolvedItem.request().bodyToString();
                        mainTab.loadPayloadIntoDeserializer(body);
                        api.logging().logToOutput("[GWTMap] Sent request payload to Deserializer");
                    }
                });
                menuItems.add(deserItem);

                JMenuItem fuzzerItem = new JMenuItem("Send to GWTMap Fuzzer");
                fuzzerItem.addActionListener(e -> {
                    if (resolvedItem != null && resolvedItem.request() != null) {
                        String url = resolvedItem.request().url();
                        String body = resolvedItem.request().bodyToString();
                        mainTab.loadPayloadIntoFuzzer(url, body);
                        api.logging().logToOutput("[GWTMap] Sent request to Fuzzer: " + url);
                    }
                });
                menuItems.add(fuzzerItem);

                return menuItems;
            }
        });

        // 3. Register Unloading Handler
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("[-] Unloading GWTMap extension and terminating thread pool...");
            try {
                mainTab.saveSession();
            } catch (Exception e) {
                api.logging().logToError("[-] Error saving session on unload: " + e.getMessage());
            }
            scanEngine.shutdown();
        });
    }
}
