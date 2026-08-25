// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer;

import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.ui.JSSourceMapExplorerTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point implementing BurpExtension for JS SourceMap Explorer.
 * Passively captures JavaScript assets, classifies app ownership, detects .map exposure,
 * unmaps original source trees, and mines for endpoints and secrets.
 *
 * @author littlespidy
 */
public class JSSourceMapExplorerExtension implements BurpExtension {

    private MontoyaApi api;
    private final JsDataStore dataStore = new JsDataStore();
    private JSSourceMapExplorerTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("JS SourceMap Explorer (littlespidy)");

        // ── 1. Create and Register Suite Tab ──
        this.mainTab = new JSSourceMapExplorerTab(api, dataStore);
        api.userInterface().registerSuiteTab("JS Explorer", mainTab);

        // ── 2. Register Context Menu Provider ──
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuItems = new ArrayList<>();

                JMenuItem sendToExplorer = new JMenuItem("Send to JS SourceMap Explorer");
                sendToExplorer.addActionListener(e -> handleSendToExplorer(event));
                menuItems.add(sendToExplorer);

                return menuItems;
            }
        });

        // ── 3. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanup();
            }
            api.logging().logToOutput("JS SourceMap Explorer extension unloaded successfully.");
        });

        api.logging().logToOutput("JS SourceMap Explorer (littlespidy) loaded successfully!");
    }

    private void handleSendToExplorer(ContextMenuEvent event) {
        HttpRequest selectedReq = null;
        HttpResponse selectedResp = null;

        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse rr = event.messageEditorRequestResponse().get().requestResponse();
            selectedReq = rr.request();
            if (rr.hasResponse()) selectedResp = rr.response();
        } else if (!event.selectedRequestResponses().isEmpty()) {
            HttpRequestResponse rr = event.selectedRequestResponses().get(0);
            selectedReq = rr.request();
            if (rr.hasResponse()) selectedResp = rr.response();
        }

        if (selectedReq != null && selectedResp != null) {
            final HttpRequest req = selectedReq;
            final HttpResponse resp = selectedResp;
            SwingUtilities.invokeLater(() -> mainTab.addCandidate(req, resp));
        }
    }
}
