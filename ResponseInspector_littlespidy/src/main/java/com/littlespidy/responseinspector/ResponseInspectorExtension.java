// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.ui.ResponseInspectorTab;

/**
 * Main Montoya API extension entry point for Response Inspector.
 * Analyzes HTTP responses for:
 * 1. Configured passwords
 * 2. Strict SSNs, RFC 1918 internal IPs, and OS server filesystem paths
 * 3. Detailed error messages, stack traces, and database leaks
 * 4. Secrets, cloud tokens, API keys, and private keys
 */
public class ResponseInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Response Inspector");

        ResponseScanEngine scanEngine = new ResponseScanEngine();
        ResponseInspectorTab mainTab = new ResponseInspectorTab(api, scanEngine);

        api.userInterface().registerSuiteTab("Response Inspector", mainTab);

        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Response Inspector unloaded.");
        });

        api.logging().logToOutput("==================================================");
        api.logging().logToOutput("Response Inspector extension loaded successfully!");
        api.logging().logToOutput("Created with the help of an AI Agent and littlespidy.");
        api.logging().logToOutput("Tabs: Passwords | PII, Network & Paths | Errors | Secrets");
        api.logging().logToOutput("Trigger: On-demand via 'Load Proxy History' button");
        api.logging().logToOutput("==================================================");
    }
}
