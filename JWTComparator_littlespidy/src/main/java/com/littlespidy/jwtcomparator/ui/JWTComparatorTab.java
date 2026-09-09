// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import burp.api.montoya.MontoyaApi;

import com.littlespidy.jwtcomparator.attacker.ui.TokenAttackerPanel;

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
    private final TokenAttackerPanel attackerPanel;

    public JWTComparatorTab(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();

        comparisonPanel = new ComparisonPanel();
        welcomeGuidePanel = new WelcomeGuidePanel(this);
        attackerPanel = new TokenAttackerPanel(api, comparisonPanel.getSlotsContainer());
        comparisonPanel.getSlotsContainer().addSlotsChangeListener(attackerPanel);

        tabbedPane.addTab("Welcome & Guide", welcomeGuidePanel);
        tabbedPane.addTab("JWT Comparator", comparisonPanel);
        tabbedPane.addTab("Token Attacker", attackerPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    public ComparisonPanel getComparisonPanel() {
        return comparisonPanel;
    }

    public TokenAttackerPanel getAttackerPanel() {
        return attackerPanel;
    }

    public void selectWelcomeTab() {
        tabbedPane.setSelectedIndex(0);
    }

    public void selectComparatorTab() {
        tabbedPane.setSelectedIndex(1);
    }

    public void selectAttackerTab() {
        tabbedPane.setSelectedIndex(2);
    }
}
