// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.InScopeDomainManager;

import javax.swing.*;
import java.awt.*;
import java.util.EnumMap;
import java.util.Map;

/**
 * Root Suite Tab for Response Inspector containing:
 * - Tab 0: Welcome & Guide onboarding dashboard
 * - Tab 1: Passwords
 * - Tab 2: PII, Network & Paths
 * - Tab 3: Errors & Exceptions
 * - Tab 4: Secrets & Tokens
 */
public class ResponseInspectorTab extends JPanel {

    private final MontoyaApi api;
    private final ResponseScanEngine scanEngine;
    private final InScopeDomainManager domainManager;
    private final JTabbedPane tabbedPane;
    private final Map<FindingCategory, CategoryFindingsPanel> panels = new EnumMap<>(FindingCategory.class);

    public ResponseInspectorTab(MontoyaApi api, ResponseScanEngine scanEngine) {
        this.api = api;
        this.scanEngine = scanEngine;
        this.domainManager = new InScopeDomainManager();

        setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();

        // Tab 0: Welcome & Guide Dashboard
        WelcomeGuidePanel welcomePanel = new WelcomeGuidePanel();
        tabbedPane.addTab("\uD83D\uDCD6 Welcome & Guide", welcomePanel);

        // Tabs 1-4: Category Findings Panels
        for (FindingCategory category : FindingCategory.values()) {
            CategoryFindingsPanel panel = new CategoryFindingsPanel(
                    api,
                    category,
                    scanEngine.getDataStore(category),
                    scanEngine,
                    domainManager,
                    this::refreshAllTabs
            );
            panels.put(category, panel);
            tabbedPane.addTab(getTabTitle(category), panel);
        }

        add(tabbedPane, BorderLayout.CENTER);
    }

    public void refreshAllTabs() {
        SwingUtilities.invokeLater(() -> {
            // Index 0 is Welcome & Guide
            int index = 1;
            for (FindingCategory category : FindingCategory.values()) {
                CategoryFindingsPanel panel = panels.get(category);
                if (panel != null) {
                    panel.refreshView();
                }
                tabbedPane.setTitleAt(index++, getTabTitle(category));
            }
        });
    }

    private String getTabTitle(FindingCategory category) {
        int count = scanEngine.getDataStore(category).size();
        String badge = count > 0 ? " (" + count + ")" : "";
        return switch (category) {
            case PASSWORD -> "\uD83D\uDD11 Passwords" + badge;
            case PII_NETWORK_PATH -> "\uD83D\uDEE1 PII, Network & Paths" + badge;
            case ERROR -> "\u26A0 Errors & Exceptions" + badge;
            case SECRET -> "\uD83D\uDD10 Secrets & Tokens" + badge;
        };
    }
}
