// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;

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
    private final HiddenAPIStorageTab_littlespidy hiddenStorageTab;
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
        this.hiddenStorageTab = new HiddenAPIStorageTab_littlespidy(api);

        this.authTestingTab.setImportTabRef(this.importTab);

        // Parameter double click navigates directly to exact request in Request & Response Viewer tab
        this.parameterCollectorTab.setOnParameterDoubleClickListener((ep, param) -> {
            if (ep != null) {
                rootTabbedPane.setSelectedComponent(requestResponseViewerTab);
                requestResponseViewerTab.selectAndDisplayEndpoint(ep);
            }
        });

        // Wire "Send to ResAPI Version Finder" from internal tabs
        this.parameterCollectorTab.setOnSendToVersionFinderListener(ep -> {
            sendEndpointToVersionFinder(ep, null);
        });

        this.importTab.setOnSendToVersionFinderListener((col, ep) -> {
            String baseUrl = (col != null && col.getTargetBaseUrl() != null && !col.getTargetBaseUrl().isBlank())
                    ? col.getTargetBaseUrl() : "https://localhost";
            sendEndpointToVersionFinder(ep, baseUrl);
        });

        this.requestResponseViewerTab.setOnSendToVersionFinderListener((col, ep) -> {
            String baseUrl = (col != null && col.getTargetBaseUrl() != null && !col.getTargetBaseUrl().isBlank())
                    ? col.getTargetBaseUrl() : "https://localhost";
            sendEndpointToVersionFinder(ep, baseUrl);
        });

        // Wire "Save to Hidden API Storage" from strategy tabs
        this.endpointDiscoveryTab.setOnSaveToHiddenStorageCallback(this.hiddenStorageTab::addEndpoint);
        this.docStrategyTab.setOnSaveToHiddenStorageCallback(this.hiddenStorageTab::addEndpoint);

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
        rootTabbedPane.addTab("Authentication Testing", authTestingTab);
        rootTabbedPane.addTab("REST API Version Finder", versionFinderTab);
        rootTabbedPane.addTab("API Documentation Strategy", docStrategyTab);
        rootTabbedPane.addTab("API Endpoint Discovery Strategy", endpointDiscoveryTab);
        rootTabbedPane.addTab("Hidden API Storage", hiddenStorageTab);

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
        if (hiddenStorageTab != null) {
            hiddenStorageTab.setEndpoints(java.util.Collections.emptyList());
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

    public HiddenAPIStorageTab_littlespidy getHiddenApiStorageTab() {
        return hiddenStorageTab;
    }

    public void sendEndpointToVersionFinder(DiscoveredEndpoint_littlespidy ep, String targetBaseUrl) {
        if (ep == null) return;
        try {
            String base = (targetBaseUrl != null && !targetBaseUrl.isBlank()) ? targetBaseUrl : "https://localhost";
            HttpRequest req = AuthTestEngine_littlespidy.buildRequest(base, ep, null, false);
            versionFinderTab.addNewSession(req, null);
            rootTabbedPane.setSelectedComponent(versionFinderTab);
        } catch (Exception ignored) {
        }
    }

    public void selectTab(Component tabComponent) {
        if (tabComponent != null) {
            rootTabbedPane.setSelectedComponent(tabComponent);
        }
    }
}
