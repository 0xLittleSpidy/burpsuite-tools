// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.ssoinspector.engine.OAuthActiveScanEngine;
import com.littlespidy.ssoinspector.model.OAuthDataStore;
import com.littlespidy.ssoinspector.storage.SSOPersistentStorageManager_littlespidy;

import javax.swing.*;
import java.awt.*;

public class SSOMainSuiteTab extends JPanel {

    private final JTabbedPane tabbedPane;
    private final OAuthTab oauthTab;

    public SSOMainSuiteTab(MontoyaApi api, OAuthDataStore dataStore, OAuthActiveScanEngine activeScanEngine) {
        this(api, dataStore, activeScanEngine, null);
    }

    public SSOMainSuiteTab(MontoyaApi api, OAuthDataStore dataStore, OAuthActiveScanEngine activeScanEngine, SSOPersistentStorageManager_littlespidy storageManager) {
        setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();
        oauthTab = new OAuthTab(api, dataStore, activeScanEngine, storageManager);

        tabbedPane.addTab("OAuth", oauthTab);

        add(tabbedPane, BorderLayout.CENTER);
    }

    public OAuthTab getOAuthTab() {
        return oauthTab;
    }

    public void selectOAuthTab() {
        tabbedPane.setSelectedComponent(oauthTab);
    }
}
