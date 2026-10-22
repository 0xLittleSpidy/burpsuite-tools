// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

/**
 * Root Suite Tab container for the API Inspector extension.
 * Hosts the ResAPI Version Finder tab, API Import tab, Parameter Collector tab,
 * Request & Response Viewer tab, Authentication Testing tab,
 * API Documentation Strategy tracking tab, and API Endpoint Discovery Strategy tracking tab.
 */
public class APIInspectorTab_littlespidy extends JPanel {

    private final JTabbedPane rootTabbedPane;
    private final ResAPIVersionFinderTab_littlespidy versionFinderTab;
    private final APIImportTab_littlespidy importTab;
    private final ParameterCollectorTab_littlespidy parameterCollectorTab;
    private final RequestResponseViewerTab_littlespidy requestResponseViewerTab;
    private final AuthTestingTab_littlespidy authTestingTab;
    private final IntruderStrategyTrackingTab_littlespidy docStrategyTab;
    private final IntruderStrategyTrackingTab_littlespidy endpointDiscoveryTab;
    private final JPanel topContainer = new JPanel(new BorderLayout());

    public APIInspectorTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        this.rootTabbedPane = new JTabbedPane();

        this.versionFinderTab = new ResAPIVersionFinderTab_littlespidy(api);
        this.importTab = new APIImportTab_littlespidy(api);
        this.parameterCollectorTab = new ParameterCollectorTab_littlespidy();
        this.requestResponseViewerTab = new RequestResponseViewerTab_littlespidy(api);
        this.authTestingTab = new AuthTestingTab_littlespidy(api);
        this.docStrategyTab = new IntruderStrategyTrackingTab_littlespidy(api, "API Documentation Intruder Strategy");
        this.endpointDiscoveryTab = new IntruderStrategyTrackingTab_littlespidy(api, "API Endpoint Discovery Intruder Strategy");

        this.authTestingTab.setImportTabRef(this.importTab);

        // Sync tabs when API Import changes
        this.importTab.addStateChangedListener(() -> {
            parameterCollectorTab.updateCollections(importTab.getAllCollections());
            requestResponseViewerTab.updateCollections(importTab.getAllCollections());
            authTestingTab.refreshCollectionsCombo();
        });

        // Sync fresh collections whenever the user selects a tab
        this.rootTabbedPane.addChangeListener(e -> {
            Component selected = rootTabbedPane.getSelectedComponent();
            if (selected == parameterCollectorTab) {
                parameterCollectorTab.updateCollections(importTab.getAllCollections());
            } else if (selected == requestResponseViewerTab) {
                requestResponseViewerTab.updateCollections(importTab.getAllCollections());
            } else if (selected == authTestingTab) {
                authTestingTab.refreshCollectionsCombo();
            }
        });

        rootTabbedPane.addTab("API Import", importTab);
        rootTabbedPane.addTab("Request & Response Viewer", requestResponseViewerTab);
        rootTabbedPane.addTab("Parameter Collector", parameterCollectorTab);
        rootTabbedPane.addTab("REST API Version Finder", versionFinderTab);
        rootTabbedPane.addTab("Authentication Testing", authTestingTab);
        rootTabbedPane.addTab("API Documentation Strategy", docStrategyTab);
        rootTabbedPane.addTab("API Endpoint Discovery Strategy", endpointDiscoveryTab);

        add(topContainer, BorderLayout.NORTH);
        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void setPersistenceManager(com.littlespidy.apiinspector.persistence.APIInspectorPersistenceManager_littlespidy persistenceManager) {
        topContainer.removeAll();
        if (persistenceManager != null) {
            topContainer.add(persistenceManager.createSessionToolbar(), BorderLayout.NORTH);
        }
        topContainer.revalidate();
        topContainer.repaint();
    }

    public void resetWorkspace() {
        if (versionFinderTab != null) {
            versionFinderTab.closeAllTabs();
        }
        if (importTab != null) {
            importTab.setCollections(java.util.Collections.emptyList());
        }
        if (parameterCollectorTab != null) {
            parameterCollectorTab.updateCollections(java.util.Collections.emptyList());
        }
        if (requestResponseViewerTab != null) {
            requestResponseViewerTab.updateCollections(java.util.Collections.emptyList());
        }
        if (authTestingTab != null) {
            authTestingTab.setProfiles(java.util.Collections.emptyList());
            authTestingTab.setResults(java.util.Collections.emptyList());
        }
        if (docStrategyTab != null) {
            docStrategyTab.restoreEntries(java.util.Collections.emptyList());
        }
        if (endpointDiscoveryTab != null) {
            endpointDiscoveryTab.restoreEntries(java.util.Collections.emptyList());
        }
    }

    public ResAPIVersionFinderTab_littlespidy getVersionFinderTab() {
        return versionFinderTab;
    }

    public APIImportTab_littlespidy getImportTab() {
        return importTab;
    }

    public ParameterCollectorTab_littlespidy getParameterCollectorTab() {
        return parameterCollectorTab;
    }

    public RequestResponseViewerTab_littlespidy getRequestResponseViewerTab() {
        return requestResponseViewerTab;
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
