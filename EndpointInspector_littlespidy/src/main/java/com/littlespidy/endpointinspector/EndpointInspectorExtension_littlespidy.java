// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.littlespidy.endpointinspector.menu.EndpointInspectorContextMenu_littlespidy;
import com.littlespidy.endpointinspector.ui.EndpointInspectorTab_littlespidy;

import javax.swing.*;

public class EndpointInspectorExtension_littlespidy implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Endpoint Inspector");

        api.logging().logToOutput("=================================================");
        api.logging().logToOutput("Endpoint Inspector v3.0 - Burp Suite Extension (by FR13ND0x7F & littlespidy)");
        api.logging().logToOutput("Hybrid Reconnaissance, Pareto Wordlists, JS Mining & Archive Diffing");
        api.logging().logToOutput("Dedicated Multi-Domain Tab Model & Persistent Session Storage");
        api.logging().logToOutput("=================================================");

        EndpointInspectorTab_littlespidy mainTab = new EndpointInspectorTab_littlespidy(api);

        api.userInterface().registerSuiteTab("Endpoint Inspector", mainTab);
        api.userInterface().registerContextMenuItemsProvider(new EndpointInspectorContextMenu_littlespidy(mainTab));

        SwingUtilities.invokeLater(mainTab::initializeSessionStartup);
    }
}
