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
 * Hosts API Import, Request & Response Viewer, Parameter Collector,
 * Config (Auth Analyzer, CORS, Input Validation), Auth Analyzer, CORS,
 * Input Validation, REST API Version Finder, Documentation Strategy,
 * Endpoint Discovery Strategy, and Hidden API Storage.
 */
public class APIInspectorTab_littlespidy extends JPanel {

    private final JTabbedPane rootTabbedPane;
    private final ResAPIVersionFinderTab_littlespidy versionFinderTab;
    private final APIImportTab_littlespidy importTab;
    private final ParameterCollectorTab_littlespidy parameterCollectorTab;
    private final RequestResponseViewerTab_littlespidy requestResponseViewerTab;
    private final ConfigTab_littlespidy configTab;
    private final AuthTestingTab_littlespidy authTestingTab;
    private final CorsTab_littlespidy corsTab;
    private final InputValidationTab_littlespidy inputValidationTab;
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
        this.corsTab = new CorsTab_littlespidy(api);
        this.inputValidationTab = new InputValidationTab_littlespidy(api);

        this.configTab = new ConfigTab_littlespidy(api, this.authTestingTab, this.corsTab, this.inputValidationTab);
        this.configTab.setRootTab(this);
        this.configTab.setImportTabRef(this.importTab);

        this.docStrategyTab = new IntruderStrategyTrackingTab_littlespidy(api, "API Documentation Intruder Strategy");
        this.endpointDiscoveryTab = new IntruderStrategyTrackingTab_littlespidy(api, "API Endpoint Discovery Intruder Strategy");
        this.hiddenStorageTab = new HiddenAPIStorageTab_littlespidy(api);

        this.authTestingTab.setConfigTab(this.configTab.getAuthAnalyzerConfigTab());
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
        this.requestResponseViewerTab.setCollectionsSupplier(this.importTab::getAllCollections);

        // Wire "Save to Hidden API Storage" from strategy tabs
        this.endpointDiscoveryTab.setOnSaveToHiddenStorageCallback(this.hiddenStorageTab::addEndpoint);
        this.docStrategyTab.setOnSaveToHiddenStorageCallback(this.hiddenStorageTab::addEndpoint);

        // Sync tabs when API Import changes
        this.importTab.addStateChangedListener(() -> {
            parameterCollectorTab.updateCollections(importTab.getAllCollections());
            requestResponseViewerTab.updateCollections(importTab.getAllCollections());
            configTab.refreshCollectionsCombo();
            authTestingTab.refreshCollectionsCombo();
        });

        // Automatically sync selected collection to Auth Analyzer Config
        this.importTab.addCollectionSelectionListener(col -> {
            if (configTab != null) {
                configTab.selectCollection(col);
            }
        });

        // Sync fresh collections whenever the user selects a tab
        this.rootTabbedPane.addChangeListener(e -> {
            Component selected = rootTabbedPane.getSelectedComponent();
            if (selected == parameterCollectorTab) {
                parameterCollectorTab.updateCollections(importTab.getAllCollections());
            } else if (selected == requestResponseViewerTab) {
                requestResponseViewerTab.updateCollections(importTab.getAllCollections());
            } else if (selected == configTab) {
                configTab.refreshCollectionsCombo();
            } else if (selected == authTestingTab) {
                authTestingTab.refreshCollectionsCombo();
            }
        });

        rootTabbedPane.addTab("API Import", importTab);
        rootTabbedPane.addTab("Request & Response Viewer", requestResponseViewerTab);
        rootTabbedPane.addTab("Parameter Collector", parameterCollectorTab);
        rootTabbedPane.addTab("Config", configTab);
        rootTabbedPane.addTab("Auth Analyzer", authTestingTab);
        rootTabbedPane.addTab("CORS", corsTab);
        rootTabbedPane.addTab("Input Validation", inputValidationTab);
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
            authTestingTab.clearAllRunners();
        }
        if (corsTab != null) {
            corsTab.clearAllRunners();
        }
        if (inputValidationTab != null) {
            inputValidationTab.clearAllRunners();
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

    public ConfigTab_littlespidy getConfigTab() {
        return configTab;
    }

    public AuthTestingTab_littlespidy getAuthTestingTab() {
        return authTestingTab;
    }

    public CorsTab_littlespidy getCorsTab() {
        return corsTab;
    }

    public InputValidationTab_littlespidy getInputValidationTab() {
        return inputValidationTab;
    }

    public AuthAnalyzerConfigTab_littlespidy getAuthAnalyzerConfigTab() {
        return configTab != null ? configTab.getAuthAnalyzerConfigTab() : null;
    }

    public void switchToAuthAnalyzer() {
        if (rootTabbedPane != null && authTestingTab != null) {
            rootTabbedPane.setSelectedComponent(authTestingTab);
        }
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
