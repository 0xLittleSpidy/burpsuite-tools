package com.littlespidy.convertposttoget;

import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import com.littlespidy.convertposttoget.scanner.ConvertPostToGetScanCheck;
import com.littlespidy.convertposttoget.ui.ConvertPostToGetTab;
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
 * Main extension entry point implementing BurpExtension for Convert POST to GET.
 *
 * @author littlespidy
 */
public class ConvertPostToGetExtension implements BurpExtension {
    private MontoyaApi api;
    private final ConvertPostToGetConfig config = new ConvertPostToGetConfig();
    private ConvertPostToGetTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Convert POST to GET (littlespidy)");

        // ── 1. Create and Register Suite Tab ──
        this.mainTab = new ConvertPostToGetTab(api, config);
        api.userInterface().registerSuiteTab("Convert POST to GET", mainTab);

        // ── 2. Register Context Menu Item ──
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuItems = new ArrayList<>();

                JMenuItem sendToConvert = new JMenuItem("Send to Convert POST to GET");
                sendToConvert.addActionListener(e -> handleSendToConvert(event));
                menuItems.add(sendToConvert);

                return menuItems;
            }
        });

        // ── 3. Register Active ScanCheck ──
        api.scanner().registerScanCheck(new ConvertPostToGetScanCheck(api, config));

        // ── 4. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanupAll();
            }
            api.logging().logToOutput("Convert POST to GET extension unloaded successfully.");
        });

        api.logging().logToOutput("Convert POST to GET (littlespidy) loaded successfully!");
    }

    private void handleSendToConvert(ContextMenuEvent event) {
        HttpRequest selectedRequest = null;
        HttpResponse selectedResponse = null;

        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse rr = event.messageEditorRequestResponse().get().requestResponse();
            selectedRequest = rr.request();
            if (rr.hasResponse()) {
                selectedResponse = rr.response();
            }
        } else if (!event.selectedRequestResponses().isEmpty()) {
            HttpRequestResponse rr = event.selectedRequestResponses().get(0);
            selectedRequest = rr.request();
            if (rr.hasResponse()) {
                selectedResponse = rr.response();
            }
        }

        if (selectedRequest != null) {
            final HttpRequest req = selectedRequest;
            final HttpResponse resp = selectedResponse;
            SwingUtilities.invokeLater(() -> mainTab.addNewSessionTab(req, resp));
        } else {
            api.logging().logToError("No valid HTTP request selected for Convert POST to GET.");
        }
    }
}
