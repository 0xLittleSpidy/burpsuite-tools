package com.littlespidy.uploadscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.uploadscanner.scanner.UploadScanCheck;
import com.littlespidy.uploadscanner.ui.UploadScannerTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main extension entry point implementing BurpExtension for Upload Scanner.
 * Registers the Upload Scanner suite tab, context menu integration,
 * scanner audit check, and unloading cleanup handler.
 *
 * @author littlespidy
 */
public class UploadScannerExtension implements BurpExtension {

    private MontoyaApi api;
    private UploadScannerTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Upload Scanner (littlespidy)");

        // ── 1. Create and Register Suite Tab ──
        this.mainTab = new UploadScannerTab(api);
        api.userInterface().registerSuiteTab("📤 Upload Scanner", mainTab);

        // ── 2. Register Context Menu Provider ──
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuItems = new ArrayList<>();

                JMenuItem sendToUploadScanner = new JMenuItem("Send to Upload Scanner");
                sendToUploadScanner.addActionListener(e -> handleSendToUploadScanner(event));
                menuItems.add(sendToUploadScanner);

                return menuItems;
            }
        });

        // ── 3. Register Active/Passive ScanCheck ──
        api.scanner().registerScanCheck(new UploadScanCheck(api));

        // ── 4. Register Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanupAll();
            }
            api.logging().logToOutput("Upload Scanner (littlespidy) unloaded successfully.");
        });

        api.logging().logToOutput("=================================================");
        api.logging().logToOutput("📤 Upload Scanner (Montoya Edition) by littlespidy");
        api.logging().logToOutput("ReDownloader Visual Markers & Triage Log Ready!");
        api.logging().logToOutput("=================================================");
    }

    private void handleSendToUploadScanner(ContextMenuEvent event) {
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
            api.logging().logToError("No valid HTTP request selected for Upload Scanner.");
        }
    }
}
