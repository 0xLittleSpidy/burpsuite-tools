// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;

import javax.swing.*;
import java.awt.*;

/**
 * Unified Configuration Tab for API Inspector.
 * Hosts sub-tabs for:
 * 1. Auth Analyzer Configuration
 * 2. CORS Testing Configuration & Techniques
 * 3. Input Validation Configuration & Attack Categories
 * 4. POST to GET Method Tampering Configuration
 */
public class ConfigTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane subTabbedPane = new JTabbedPane();

    private final AuthAnalyzerConfigTab_littlespidy authAnalyzerConfigTab;
    private final CorsConfigPanel_littlespidy corsConfigPanel;
    private final InputValidationConfigPanel_littlespidy inputValidationConfigPanel;
    private final PostToGetConfigPanel_littlespidy postToGetConfigPanel;

    public ConfigTab_littlespidy(
            MontoyaApi api,
            AuthTestingTab_littlespidy authTestingTab,
            CorsTab_littlespidy corsTab,
            InputValidationTab_littlespidy inputValidationTab) {
        this(api, authTestingTab, corsTab, inputValidationTab, null);
    }

    public ConfigTab_littlespidy(
            MontoyaApi api,
            AuthTestingTab_littlespidy authTestingTab,
            CorsTab_littlespidy corsTab,
            InputValidationTab_littlespidy inputValidationTab,
            PostToGetTab_littlespidy postToGetTab) {
        super(new BorderLayout());
        this.api = api;

        this.authAnalyzerConfigTab = new AuthAnalyzerConfigTab_littlespidy(api, authTestingTab);
        this.corsConfigPanel = new CorsConfigPanel_littlespidy(api);
        this.inputValidationConfigPanel = new InputValidationConfigPanel_littlespidy(api);
        this.postToGetConfigPanel = new PostToGetConfigPanel_littlespidy(api);

        if (corsTab != null) {
            this.corsConfigPanel.setCorsTab(corsTab);
        }
        if (inputValidationTab != null) {
            this.inputValidationConfigPanel.setInputValidationTab(inputValidationTab);
        }
        if (postToGetTab != null) {
            this.postToGetConfigPanel.setPostToGetTab(postToGetTab);
        }

        // Synchronize available Auth Profiles from Auth Analyzer to sub-panels
        this.authAnalyzerConfigTab.addStateChangedListener(this::syncAuthProfilesToSubPanels);
        syncAuthProfilesToSubPanels();

        initComponents();
    }

    public void setPostToGetTab(PostToGetTab_littlespidy tab) {
        if (postToGetConfigPanel != null) {
            postToGetConfigPanel.setPostToGetTab(tab);
        }
    }

    public void syncAuthProfilesToSubPanels() {
        if (authAnalyzerConfigTab != null) {
            java.util.List<com.littlespidy.apiinspector.model.AuthProfile_littlespidy> profiles = authAnalyzerConfigTab.getAllProfiles();
            corsConfigPanel.updateAvailableProfiles(profiles);
            inputValidationConfigPanel.updateAvailableProfiles(profiles);
            postToGetConfigPanel.updateAvailableProfiles(profiles);
        }
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.authAnalyzerConfigTab.setRootTab(rootTab);
        this.corsConfigPanel.setRootTab(rootTab);
        this.inputValidationConfigPanel.setRootTab(rootTab);
        this.postToGetConfigPanel.setRootTab(rootTab);
    }

    public void setImportTabRef(APIImportTab_littlespidy importTabRef) {
        this.authAnalyzerConfigTab.setImportTabRef(importTabRef);
        this.corsConfigPanel.setImportTabRef(importTabRef);
        this.inputValidationConfigPanel.setImportTabRef(importTabRef);
        this.postToGetConfigPanel.setImportTabRef(importTabRef);
    }

    public void refreshCollectionsCombo() {
        this.authAnalyzerConfigTab.refreshCollectionsCombo();
        this.corsConfigPanel.refreshCollectionsCombo();
        this.inputValidationConfigPanel.refreshCollectionsCombo();
        this.postToGetConfigPanel.refreshCollectionsCombo();
        syncAuthProfilesToSubPanels();
    }

    public void selectCollection(ImportedCollection_littlespidy col) {
        if (this.authAnalyzerConfigTab != null) {
            this.authAnalyzerConfigTab.selectCollection(col);
        }
        if (this.corsConfigPanel != null) {
            this.corsConfigPanel.selectCollection(col);
        }
        if (this.inputValidationConfigPanel != null) {
            this.inputValidationConfigPanel.selectCollection(col);
        }
        if (this.postToGetConfigPanel != null) {
            this.postToGetConfigPanel.selectCollection(col);
        }
    }

    public AuthAnalyzerConfigTab_littlespidy getAuthAnalyzerConfigTab() {
        return authAnalyzerConfigTab;
    }

    public CorsConfigPanel_littlespidy getCorsConfigPanel() {
        return corsConfigPanel;
    }

    public InputValidationConfigPanel_littlespidy getInputValidationConfigPanel() {
        return inputValidationConfigPanel;
    }

    public PostToGetConfigPanel_littlespidy getPostToGetConfigPanel() {
        return postToGetConfigPanel;
    }

    public void selectCorsConfig() {
        subTabbedPane.setSelectedComponent(corsConfigPanel);
    }

    public void selectInputValidationConfig() {
        subTabbedPane.setSelectedComponent(inputValidationConfigPanel);
    }

    public void selectAuthConfig() {
        subTabbedPane.setSelectedComponent(authAnalyzerConfigTab);
    }

    public void selectPostToGetConfig() {
        subTabbedPane.setSelectedComponent(postToGetConfigPanel);
    }

    private void initComponents() {
        subTabbedPane.addTab("Auth Analyzer", authAnalyzerConfigTab);
        subTabbedPane.addTab("CORS", corsConfigPanel);
        subTabbedPane.addTab("Input Validation", inputValidationConfigPanel);
        subTabbedPane.addTab("POST to GET", postToGetConfigPanel);

        add(subTabbedPane, BorderLayout.CENTER);
    }
}
