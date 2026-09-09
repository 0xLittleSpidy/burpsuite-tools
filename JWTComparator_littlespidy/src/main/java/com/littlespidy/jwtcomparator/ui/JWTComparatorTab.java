// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

/**
 * Root Suite tab component for JWT Comparator.
 */
public class JWTComparatorTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane tabbedPane;
    private final ComparisonPanel comparisonPanel;
    private final WelcomeGuidePanel welcomeGuidePanel;

    public JWTComparatorTab(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();

        comparisonPanel = new ComparisonPanel();
        welcomeGuidePanel = new WelcomeGuidePanel();

        tabbedPane.addTab("JWT Comparator", comparisonPanel);
        tabbedPane.addTab("Welcome & Guide", welcomeGuidePanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    public ComparisonPanel getComparisonPanel() {
        return comparisonPanel;
    }

    public void selectComparatorTab() {
        tabbedPane.setSelectedIndex(0);
    }
}
