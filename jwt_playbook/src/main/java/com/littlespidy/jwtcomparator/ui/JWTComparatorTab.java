// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import burp.api.montoya.MontoyaApi;

import com.littlespidy.jwtcomparator.attacker.ui.TokenAttackerPanel;

import javax.swing.*;
import java.awt.*;

/**
 * Root Suite tab component for jwt_playbook.
 */
public class JWTComparatorTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane tabbedPane;
    private final ComparisonPanel comparisonPanel;
    private final WelcomeGuidePanel welcomeGuidePanel;
    private final TokenAttackerPanel attackerPanel;
    private final JwtAttackWorkbenchPanel attackWorkbenchPanel;
    private final JwtKeyOperationsPanel keyOperationsPanel;
    private final LiveJwtProbePanel liveProbePanel;
    private final JTabbedPane offlineTabs;
    private final JTabbedPane attackTabs;

    public JWTComparatorTab(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();

        comparisonPanel = new ComparisonPanel();
        welcomeGuidePanel = new WelcomeGuidePanel(this);
        attackerPanel = new TokenAttackerPanel(api, comparisonPanel.getSlotsContainer());
        comparisonPanel.getSlotsContainer().addSlotsChangeListener(attackerPanel);

        offlineTabs = new JTabbedPane();
        offlineTabs.addTab("Welcome & Guide", welcomeGuidePanel);
        offlineTabs.addTab("JWT Comparator", comparisonPanel);
        attackTabs = new JTabbedPane();
        attackWorkbenchPanel = new JwtAttackWorkbenchPanel(comparisonPanel.getSlotsContainer());
        keyOperationsPanel = new JwtKeyOperationsPanel(api);
        attackWorkbenchPanel.setKeyOperationsPanel(keyOperationsPanel);
        liveProbePanel = new LiveJwtProbePanel(api, attackWorkbenchPanel);
        attackTabs.addTab("JWT Attack Workbench", attackWorkbenchPanel);
        attackTabs.addTab("Keys & Verification", keyOperationsPanel);
        attackTabs.addTab("Live JWT Probes", liveProbePanel);
        attackTabs.addTab("Token Access Matrix", attackerPanel);
        tabbedPane.addTab("Offline Analysis", offlineTabs);
        tabbedPane.addTab("Attack", attackTabs);

        add(tabbedPane, BorderLayout.CENTER);
    }

    public ComparisonPanel getComparisonPanel() {
        return comparisonPanel;
    }

    public TokenAttackerPanel getAttackerPanel() {
        return attackerPanel;
    }

    public LiveJwtProbePanel getLiveProbePanel() { return liveProbePanel; }

    public void selectWelcomeTab() {
        tabbedPane.setSelectedIndex(0);
        offlineTabs.setSelectedIndex(0);
    }

    public void selectComparatorTab() {
        tabbedPane.setSelectedIndex(0);
        offlineTabs.setSelectedIndex(1);
    }

    public void selectAttackerTab() {
        tabbedPane.setSelectedIndex(1);
        attackTabs.setSelectedIndex(3);
    }

    public void selectAttackWorkbenchTab() {
        tabbedPane.setSelectedIndex(1);
        attackTabs.setSelectedIndex(0);
    }

    public void close() { attackWorkbenchPanel.stopKeyServer(); liveProbePanel.stopProbes(); attackerPanel.shutdown(); }

    public void selectLiveProbeTab() {
        tabbedPane.setSelectedIndex(1);
        attackTabs.setSelectedIndex(2);
    }
}
