package com.littlespidy.inputvalidationfuzzer;

import com.littlespidy.inputvalidationfuzzer.model.FuzzerConfig;
import com.littlespidy.inputvalidationfuzzer.scanner.InputValidationScanCheck;
import com.littlespidy.inputvalidationfuzzer.ui.InputValidationFuzzerTab;
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
 * Main extension entry point implementing BurpExtension.
 * Registers the Input Validation Fuzzer suite tab, context menu actions,
 * and active ScanCheck scanner integration.
 *
 * @author littlespidy
 */
public class InputValidationFuzzerExtension implements BurpExtension {
    private MontoyaApi api;
    private final FuzzerConfig config = new FuzzerConfig();
    private InputValidationFuzzerTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Input Validation Fuzzer (littlespidy)");

        // ── 1. Create and Register Suite Tab ──
        this.mainTab = new InputValidationFuzzerTab(api, config);
        api.userInterface().registerSuiteTab("Input Validation Fuzzer", mainTab);

        // ── 2. Register Context Menu Item: "Send to Fuzzer" ──
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuItems = new ArrayList<>();

                JMenuItem sendToFuzzer = new JMenuItem("Send to Input Validation Fuzzer");
                sendToFuzzer.addActionListener(e -> handleSendToFuzzer(event));
                menuItems.add(sendToFuzzer);

                return menuItems;
            }
        });

        // ── 3. Register Active ScanCheck for Burp Scanner ──
        api.scanner().registerScanCheck(new InputValidationScanCheck(api, config));

        // ── 4. Register Extension Unloading Handler ──
        api.extension().registerUnloadingHandler(() -> {
            if (mainTab != null) {
                mainTab.cleanupAll();
            }
            api.logging().logToOutput("Input Validation Fuzzer extension unloaded successfully.");
        });

        api.logging().logToOutput("Input Validation Fuzzer (littlespidy) loaded successfully!");
    }

    private void handleSendToFuzzer(ContextMenuEvent event) {
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
            api.logging().logToError("No valid HTTP request selected for Input Validation Fuzzer.");
        }
    }
}
