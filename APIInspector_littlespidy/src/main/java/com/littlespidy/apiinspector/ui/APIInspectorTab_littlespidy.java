// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

/**
 * Root Suite Tab container for the API Inspector extension.
 * Hosts the ResAPI Version Finder tab, API Documentation Strategy tracking tab,
 * and API Endpoint Discovery Strategy tracking tab.
 */
public class APIInspectorTab_littlespidy extends JPanel {

    private final JTabbedPane rootTabbedPane;
    private final ResAPIVersionFinderTab_littlespidy versionFinderTab;
    private final APIImportTab_littlespidy importTab;
    private final AuthTestingTab_littlespidy authTestingTab;
    private final IntruderStrategyTrackingTab_littlespidy docStrategyTab;
    private final IntruderStrategyTrackingTab_littlespidy endpointDiscoveryTab;

    public APIInspectorTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.rootTabbedPane = new JTabbedPane();

        this.versionFinderTab = new ResAPIVersionFinderTab_littlespidy(api);
        this.importTab = new APIImportTab_littlespidy(api);
        this.authTestingTab = new AuthTestingTab_littlespidy(api);
        this.docStrategyTab = new IntruderStrategyTrackingTab_littlespidy(api, "API Documentation Intruder Strategy");
        this.endpointDiscoveryTab = new IntruderStrategyTrackingTab_littlespidy(api, "API Endpoint Discovery Intruder Strategy");

        this.authTestingTab.setImportTabRef(this.importTab);

        rootTabbedPane.addTab("ResAPI Version Finder", versionFinderTab);
        rootTabbedPane.addTab("API Import", importTab);
        rootTabbedPane.addTab("Authentication Testing", authTestingTab);
        rootTabbedPane.addTab("API Documentation Strategy", docStrategyTab);
        rootTabbedPane.addTab("API Endpoint Discovery Strategy", endpointDiscoveryTab);

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public ResAPIVersionFinderTab_littlespidy getVersionFinderTab() {
        return versionFinderTab;
    }

    public APIImportTab_littlespidy getImportTab() {
        return importTab;
    }

    public AuthTestingTab_littlespidy getAuthTestingTab() {
        return authTestingTab;
    }

    public IntruderStrategyTrackingTab_littlespidy getDocStrategyTab() {
        return docStrategyTab;
    }

    public IntruderStrategyTrackingTab_littlespidy getEndpointDiscoveryTab() {
        return endpointDiscoveryTab;
    }

    public void selectTab(Component tabComponent) {
        if (tabComponent != null) {
            rootTabbedPane.setSelectedComponent(tabComponent);
        }
    }
}
