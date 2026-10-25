// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.headerinspector.storage.HeaderPersistentStorageManager_littlespidy;
import com.littlespidy.headerinspector.cache.model.CacheDataStore;
import com.littlespidy.headerinspector.cache.ui.CacheInspectorTab;
import com.littlespidy.headerinspector.collector.model.HeaderCollectorDataStore;
import com.littlespidy.headerinspector.collector.ui.HeaderCollectorTab;
import com.littlespidy.headerinspector.csp.model.CSPDataStore;
import com.littlespidy.headerinspector.csp.ui.CSPInspectorTab;
import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.hsts.ui.HSTSInspectorTab;
import com.littlespidy.headerinspector.method.model.MethodCollectorDataStore;
import com.littlespidy.headerinspector.method.ui.MethodCollectorTab;
import com.littlespidy.headerinspector.status.model.StatusCollectorDataStore;
import com.littlespidy.headerinspector.status.ui.StatusCollectorTab;

import javax.swing.*;
import java.awt.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Root suite tab for Header Inspector containing:
 * 1. Header Collector (Request & Response headers grouped by name, unique values, associated domains)
 * 2. Method Collector (HTTP methods aggregated by verb, safe/idempotent/cacheable semantics from http.dev)
 * 3. Status Collector (HTTP status codes grouped by class & code, client actions, SEO impact from http.dev)
 * 4. Cache Inspector (Caching directives, CDN headers, master-detail editors)
 * 5. CSP Inspector (Content Security Policy auditing with Inbuilt Google CSP Evaluator)
 * 6. HSTS Inspector (Strict-Transport-Security auditing, max-age, preload readiness)
 *
 * Coordinates unified Proxy history ingestion so loading in one tab synchronizes across all tabs.
 *
 * @author littlespidy
 */
public class HeaderInspectorRootTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane mainTabbedPane = new JTabbedPane();

    private final HeaderCollectorDataStore collectorDataStore = new HeaderCollectorDataStore();
    private final MethodCollectorDataStore methodDataStore = new MethodCollectorDataStore();
    private final StatusCollectorDataStore statusDataStore = new StatusCollectorDataStore();
    private final CacheDataStore cacheDataStore = new CacheDataStore();
    private final CSPDataStore cspDataStore = new CSPDataStore();
    private final HSTSDataStore hstsDataStore = new HSTSDataStore();

    private final HeaderCollectorTab collectorTab;
    private final MethodCollectorTab methodTab;
    private final StatusCollectorTab statusTab;
    private final CacheInspectorTab cacheTab;
    private final CSPInspectorTab cspTab;
    private final HSTSInspectorTab hstsTab;

    private final ProxyHistoryCoordinator coordinator;
    private final HeaderPersistentStorageManager_littlespidy storageManager;

    public HeaderInspectorRootTab(MontoyaApi api) {
        this(api, null);
    }

    public HeaderInspectorRootTab(MontoyaApi api, HeaderPersistentStorageManager_littlespidy storageManager) {
        super(new BorderLayout());
        this.api = api;
        this.storageManager = storageManager;

        // Instantiate Tabs
        this.collectorTab = new HeaderCollectorTab(api, collectorDataStore);
        this.methodTab    = new MethodCollectorTab(api, methodDataStore);
        this.statusTab    = new StatusCollectorTab(api, statusDataStore);
        this.cacheTab     = new CacheInspectorTab(api, cacheDataStore);
        this.cspTab       = new CSPInspectorTab(api, cspDataStore);
        this.hstsTab      = new HSTSInspectorTab(api, hstsDataStore);

        // Setup Coordinator
        this.coordinator = new ProxyHistoryCoordinator(
                api,
                collectorDataStore,
                methodDataStore,
                statusDataStore,
                cacheDataStore,
                cspDataStore,
                hstsDataStore
        );
        if (storageManager != null) {
            this.coordinator.setStorageManager(storageManager);
            this.storageManager.bindDataStores(
                    collectorDataStore,
                    methodDataStore,
                    statusDataStore,
                    cacheDataStore,
                    cspDataStore,
                    hstsDataStore
            );
        }
        this.coordinator.registerTabs(collectorTab, methodTab, statusTab, cacheTab, cspTab, hstsTab);

        collectorTab.setCoordinator(coordinator);
        methodTab.setCoordinator(coordinator);
        statusTab.setCoordinator(coordinator);
        cacheTab.setCoordinator(coordinator);
        cspTab.setCoordinator(coordinator);
        hstsTab.setCoordinator(coordinator);

        // Add core inspector/collector workspace tabs (No Emojis)
        mainTabbedPane.addTab("Header Collector", collectorTab);
        mainTabbedPane.addTab("Method Collector", methodTab);
        mainTabbedPane.addTab("Status Collector", statusTab);
        mainTabbedPane.addTab("Cache Inspector", cacheTab);
        mainTabbedPane.addTab("CSP Inspector", cspTab);
        mainTabbedPane.addTab("HSTS Inspector", hstsTab);

        if (storageManager != null) {
            add(storageManager.createSessionToolbarComponent(this, this::refreshAllTabs), BorderLayout.NORTH);
        }
        add(mainTabbedPane, BorderLayout.CENTER);
    }

    public void refreshAllTabs() {
        if (collectorTab != null) collectorTab.refreshView();
        if (methodTab != null) methodTab.refreshView();
        if (statusTab != null) statusTab.refreshView();
        if (cacheTab != null) cacheTab.refreshView();
        if (cspTab != null) cspTab.refreshView();
        if (hstsTab != null) hstsTab.refreshView();
    }

    public void cleanup() {
        if (cacheTab != null) cacheTab.cleanup();
        if (cspTab != null) cspTab.cleanup();
        if (hstsTab != null) hstsTab.cleanup();
    }
}
