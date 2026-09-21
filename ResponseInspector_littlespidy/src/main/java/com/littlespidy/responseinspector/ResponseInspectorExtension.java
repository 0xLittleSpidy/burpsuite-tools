// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.ui.ResponseInspectorTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Main Montoya API extension entry point for Response Inspector.
 * Analyzes HTTP response bodies for:
 * 1. Configured passwords
 * 2. Strict SSNs, RFC 1918 internal IPs, and OS server filesystem paths
 * 3. Detailed error messages, stack traces, and database leaks
 * 4. Secrets, cloud tokens, API keys, and private keys
 * 5. Developer comments (TODO/FIXME, credentials, debug hints, general)
 */
public class ResponseInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Response Inspector");

        ResponseScanEngine scanEngine = new ResponseScanEngine();
        ResponseInspectorTab mainTab = new ResponseInspectorTab(api, scanEngine);

        api.userInterface().registerSuiteTab("Response Inspector", mainTab);

        // 1. Live Repeater HTTP Handler: collects responses sent from Burp Repeater
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                if (responseReceived.toolSource().isFromTool(ToolType.REPEATER)) {
                    HttpRequestResponse item = HttpRequestResponse.httpRequestResponse(
                            responseReceived.initiatingRequest(),
                            responseReceived,
                            responseReceived.annotations()
                    );
                    scanEngine.addRepeaterItem(item);
                }
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        // 2. Suite-wide Context Menu: "Send to Response Inspector"
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuItems = new ArrayList<>();
                JMenuItem sendItem = new JMenuItem("Send to Response Inspector");
                sendItem.addActionListener(e -> {
                    List<HttpRequestResponse> items = new ArrayList<>();
                    if (event.messageEditorRequestResponse().isPresent()) {
                        items.add(event.messageEditorRequestResponse().get().requestResponse());
                    }
                    if (event.selectedRequestResponses() != null) {
                        items.addAll(event.selectedRequestResponses());
                    }
                    if (!items.isEmpty()) {
                        int addedCount = 0;
                        for (HttpRequestResponse item : items) {
                            if (item != null && item.hasResponse()) {
                                scanEngine.addRepeaterItem(item);
                                addedCount += scanEngine.scanItem(item);
                            }
                        }
                        final int findingsCount = addedCount;
                        mainTab.refreshAllTabs();
                        api.logging().logToOutput("[Response Inspector] Scanned " + items.size() + " items from context menu. New findings: " + findingsCount);
                    }
                });
                menuItems.add(sendItem);
                return menuItems;
            }
        });

        api.extension().registerUnloadingHandler(() ->
            api.logging().logToOutput("Response Inspector unloaded.")
        );

        api.logging().logToOutput("==================================================");
        api.logging().logToOutput("Response Inspector extension loaded successfully!");
        api.logging().logToOutput("Created with the help of an AI Agent and littlespidy.");
        api.logging().logToOutput("Tabs: Passwords | PII, Network & Paths | Errors | Secrets | Comments");
        api.logging().logToOutput("Triggers: On-demand via 'Load Proxy' and 'Load from Repeater' buttons");
        api.logging().logToOutput("Filters: JS, CSS, PNG, images, fonts, and static media files excluded from loading.");
        api.logging().logToOutput("Inspection: Strictly analyzes response bodies to eliminate header false positives.");
        api.logging().logToOutput("==================================================");
    }
}
