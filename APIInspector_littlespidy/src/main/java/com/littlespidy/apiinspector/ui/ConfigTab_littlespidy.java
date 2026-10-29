// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

/**
 * Unified Configuration Tab for API Inspector.
 * Hosts sub-tabs for:
 * 1. Auth Analyzer Configuration
 * 2. CORS Testing Configuration & Techniques
 * 3. Input Validation Configuration & Attack Categories
 */
public class ConfigTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane subTabbedPane = new JTabbedPane();

    private final AuthAnalyzerConfigTab_littlespidy authAnalyzerConfigTab;
    private final CorsConfigPanel_littlespidy corsConfigPanel;
    private final InputValidationConfigPanel_littlespidy inputValidationConfigPanel;

    public ConfigTab_littlespidy(
            MontoyaApi api,
            AuthTestingTab_littlespidy authTestingTab,
            CorsTab_littlespidy corsTab,
            InputValidationTab_littlespidy inputValidationTab) {
        super(new BorderLayout());
        this.api = api;

        this.authAnalyzerConfigTab = new AuthAnalyzerConfigTab_littlespidy(api, authTestingTab);
        this.corsConfigPanel = new CorsConfigPanel_littlespidy(api);
        this.inputValidationConfigPanel = new InputValidationConfigPanel_littlespidy(api);

        if (corsTab != null) {
            this.corsConfigPanel.setCorsTab(corsTab);
        }
        if (inputValidationTab != null) {
            this.inputValidationConfigPanel.setInputValidationTab(inputValidationTab);
        }

        initComponents();
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.authAnalyzerConfigTab.setRootTab(rootTab);
        this.corsConfigPanel.setRootTab(rootTab);
        this.inputValidationConfigPanel.setRootTab(rootTab);
    }

    public void setImportTabRef(APIImportTab_littlespidy importTabRef) {
        this.authAnalyzerConfigTab.setImportTabRef(importTabRef);
    }

    public void refreshCollectionsCombo() {
        this.authAnalyzerConfigTab.refreshCollectionsCombo();
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

    public void selectCorsConfig() {
        subTabbedPane.setSelectedComponent(corsConfigPanel);
    }

    public void selectInputValidationConfig() {
        subTabbedPane.setSelectedComponent(inputValidationConfigPanel);
    }

    public void selectAuthConfig() {
        subTabbedPane.setSelectedComponent(authAnalyzerConfigTab);
    }

    private void initComponents() {
        subTabbedPane.addTab("CORS", corsConfigPanel);
        subTabbedPane.addTab("Input Validation", inputValidationConfigPanel);
        subTabbedPane.addTab("Auth Analyzer", authAnalyzerConfigTab);

        add(subTabbedPane, BorderLayout.CENTER);
    }
}
