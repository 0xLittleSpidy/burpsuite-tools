// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.wordpressinspector.model.WordPressDataStore_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressTarget_littlespidy;
import com.littlespidy.wordpressinspector.storage.WordPressPreferencesManager_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Main Burp Suite extension Suite Tab for WordPress Inspector.
 * Holds the top-level JTabbedPane containing the Configuration tab and individual Domain parent tabs.
 */
public class WordPressInspectorSuiteTab_littlespidy extends JPanel implements WordPressDataStore_littlespidy.DataStoreListener {

    private final MontoyaApi api;
    private final WordPressDataStore_littlespidy dataStore;
    private final WordPressPreferencesManager_littlespidy prefsManager;

    private final JTabbedPane topTabbedPane;
    private final ConfigurationTab_littlespidy configTab;
    private final Map<String, DomainParentTab_littlespidy> domainTabs = new ConcurrentHashMap<>();

    public WordPressInspectorSuiteTab_littlespidy(
            MontoyaApi api,
            WordPressDataStore_littlespidy dataStore,
            WordPressPreferencesManager_littlespidy prefsManager
    ) {
        super(new BorderLayout());
        this.api = api;
        this.dataStore = dataStore;
        this.prefsManager = prefsManager;

        dataStore.addListener(this);

        topTabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);

        // Tab 0: Permanent Configuration Tab
        configTab = new ConfigurationTab_littlespidy(api, dataStore, prefsManager, this);
        topTabbedPane.addTab("Configuration", configTab);

        add(topTabbedPane, BorderLayout.CENTER);
    }

    public synchronized void openDomainTab(WordPressTarget_littlespidy target) {
        String key = target.getRootDomain();
        if (domainTabs.containsKey(key)) {
            // Activate existing tab
            DomainParentTab_littlespidy existing = domainTabs.get(key);
            topTabbedPane.setSelectedComponent(existing);
            return;
        }

        DomainParentTab_littlespidy domainTab = new DomainParentTab_littlespidy(api, dataStore, target);
        domainTabs.put(key, domainTab);

        topTabbedPane.addTab(key, domainTab);
        int tabIndex = topTabbedPane.indexOfComponent(domainTab);

        CloseableTabHeader_littlespidy header = new CloseableTabHeader_littlespidy(key, () -> closeDomainTab(key));
        topTabbedPane.setTabComponentAt(tabIndex, header);

        topTabbedPane.setSelectedComponent(domainTab);
    }

    public synchronized void closeDomainTab(String rootDomain) {
        DomainParentTab_littlespidy tab = domainTabs.remove(rootDomain);
        if (tab != null) {
            topTabbedPane.remove(tab);
            dataStore.removeTarget(rootDomain);
        }
    }

    @Override
    public void onTargetAdded(WordPressTarget_littlespidy target) {
        SwingUtilities.invokeLater(() -> openDomainTab(target));
    }

    @Override
    public void onTargetRemoved(WordPressTarget_littlespidy target) {
        SwingUtilities.invokeLater(() -> {
            DomainParentTab_littlespidy tab = domainTabs.remove(target.getRootDomain());
            if (tab != null) {
                topTabbedPane.remove(tab);
            }
        });
    }

    public ConfigurationTab_littlespidy getConfigTab() {
        return configTab;
    }
}
