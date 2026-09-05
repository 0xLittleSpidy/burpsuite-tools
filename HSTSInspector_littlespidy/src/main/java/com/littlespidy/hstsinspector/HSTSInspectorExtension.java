// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.hstsinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.hstsinspector.model.HSTSDataStore;
import com.littlespidy.hstsinspector.ui.HSTSInspectorTab;

import javax.swing.*;

/**
 * Entry point for the HSTS Inspector Burp Suite extension.
 * Registers the extension and installs the custom UI tab.
 *
 * @author littlespidy
 */
public class HSTSInspectorExtension implements BurpExtension {

    private HSTSInspectorTab inspectorTab;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("HSTS Inspector");

        HSTSDataStore dataStore = new HSTSDataStore();
        inspectorTab = new HSTSInspectorTab(api, dataStore);

        SwingUtilities.invokeLater(() ->
            api.userInterface().registerSuiteTab("HSTS Inspector", inspectorTab)
        );

        api.extension().registerUnloadingHandler(() -> {
            if (inspectorTab != null) inspectorTab.cleanup();
        });

        api.logging().logToOutput("HSTS Inspector loaded successfully.");
    }
}
