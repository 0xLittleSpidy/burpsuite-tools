// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector;

import burp.api.montoya.MontoyaApi;
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
 * 0. 📖 Welcome & Guide (Single unified onboarding dashboard and module guide)
 * 1. 📋 Header Collector (Request & Response headers grouped by name, unique values, associated domains)
 * 2. ⚡ Method Collector (HTTP methods aggregated by verb, safe/idempotent/cacheable semantics from http.dev)
 * 3. 🔢 Status Collector (HTTP status codes grouped by class & code, client actions, SEO impact from http.dev)
 * 4. 🗄️ Cache Inspector (Caching directives, CDN headers, master-detail editors)
 * 5. 🛡️ CSP Inspector (Content Security Policy auditing with Inbuilt Google CSP Evaluator)
 * 6. 🔒 HSTS Inspector (Strict-Transport-Security auditing, max-age, preload readiness)
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

    public HeaderInspectorRootTab(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

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
        this.coordinator.registerTabs(collectorTab, methodTab, statusTab, cacheTab, cspTab, hstsTab);

        collectorTab.setCoordinator(coordinator);
        methodTab.setCoordinator(coordinator);
        statusTab.setCoordinator(coordinator);
        cacheTab.setCoordinator(coordinator);
        cspTab.setCoordinator(coordinator);
        hstsTab.setCoordinator(coordinator);

        // Add sub-tabs: Welcome & Guide followed by the five inspector/collector workspaces
        mainTabbedPane.addTab("📖 Welcome & Guide", createWelcomePanel());
        mainTabbedPane.addTab("📋 Header Collector", collectorTab);
        mainTabbedPane.addTab("⚡ Method Collector", methodTab);
        mainTabbedPane.addTab("🔢 Status Collector", statusTab);
        mainTabbedPane.addTab("🗄️ Cache Inspector", cacheTab);
        mainTabbedPane.addTab("🛡️ CSP Inspector", cspTab);
        mainTabbedPane.addTab("🔒 HSTS Inspector", hstsTab);

        add(mainTabbedPane, BorderLayout.CENTER);
    }

    private JComponent createWelcomePanel() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        // ── 1. Header Banner ──
        JPanel headerPanel = new JPanel(new BorderLayout(8, 8));
        headerPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel titleLabel = new JLabel("📋 Header & Protocol Inspector Suite");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea(
            "Consolidated HTTP Protocol Intelligence & Security Auditing Suite for Burp Suite Professional and Community Edition.\n"
            + "Unifies global header harvesting, HTTP method auditing with RFC semantics, response status code intelligence from http.dev, "
            + "cache & CDN security analysis, Content Security Policy evaluation using Google's official engine, and HSTS preload auditing into a single synchronized interface."
        );
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);

        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);
        content.add(headerPanel);
        content.add(Box.createVerticalStrut(15));

        // ── 2. Unified Ingestion Callout ──
        JPanel calloutPanel = new JPanel(new BorderLayout(8, 8));
        calloutPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        calloutPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(25, 118, 210), 1, true),
            BorderFactory.createEmptyBorder(12, 14, 12, 14)
        ));
        calloutPanel.setBackground(new Color(235, 245, 255));

        JLabel calloutTitle = new JLabel("⚡ One-Click Synchronized Ingestion (Zero Passive CPU Overhead)");
        calloutTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        calloutTitle.setForeground(new Color(13, 71, 161));

        JTextArea calloutText = new JTextArea(
            "Clicking 'Load Proxy History' in ANY tab automatically synchronizes data extraction across all six modules "
            + "simultaneously in a single background worker pass. In-scope gating ([x] In-Scope Only) filters third-party telemetry "
            + "before memory allocation, preventing UI hangs or JVM garbage collection spikes."
        );
        calloutText.setEditable(false);
        calloutText.setOpaque(false);
        calloutText.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        calloutText.setLineWrap(true);
        calloutText.setWrapStyleWord(true);

        calloutPanel.add(calloutTitle, BorderLayout.NORTH);
        calloutPanel.add(calloutText, BorderLayout.CENTER);
        content.add(calloutPanel);
        content.add(Box.createVerticalStrut(20));

        // ── 3. Feature Cards (3x2 Grid) ──
        JPanel cardsGrid = new JPanel(new GridLayout(3, 2, 16, 16));
        cardsGrid.setAlignmentX(Component.LEFT_ALIGNMENT);

        cardsGrid.add(createModuleCard(
            "📋 Header Collector",
            "Harvests every HTTP Request and Response header across proxy history. Groups multiple distinct values under "
            + "their respective header names, attributes unique name-value pairs to target domains, offers 4-pillar deep linking "
            + "with search marking, and one-click TSV export.",
            "Switch to Headers",
            () -> mainTabbedPane.setSelectedIndex(1)
        ));

        cardsGrid.add(createModuleCard(
            "⚡ Method Collector (NEW)",
            "Aggregates all HTTP request methods (GET, POST, PUT, DELETE, PATCH, etc.) across traffic. Classifies RFC 9110 safety, "
            + "idempotency, and cacheability properties, correlates endpoints and target domains, and embeds offline documentation from http.dev.",
            "Switch to Methods",
            () -> mainTabbedPane.setSelectedIndex(2)
        ));

        cardsGrid.add(createModuleCard(
            "🔢 Status Collector (NEW)",
            "Aggregates all HTTP response status codes (standard 1xx-5xx plus Cloudflare, Nginx, Akamai, and Edgio vendor codes). "
            + "Correlates status classes, meanings, recommended client actions, SEO impact, and embeds offline reference documentation from http.dev.",
            "Switch to Statuses",
            () -> mainTabbedPane.setSelectedIndex(3)
        ));

        cardsGrid.add(createModuleCard(
            "🗄️ Cache Inspector",
            "Audits 12 key caching directives and CDN headers (Cache-Control, Pragma, Expires, Age, ETag, Vary, CF-Cache-Status, etc.). "
            + "Quickly identifies unkeyed input poisoning risks, web cache deception vectors, and private response leakage. "
            + "Multi-select filtering by method, status code, and content type.",
            "Switch to Cache Inspector",
            () -> mainTabbedPane.setSelectedIndex(4)
        ));

        cardsGrid.add(createModuleCard(
            "🛡️ CSP Inspector (Inbuilt Google CSP Evaluator)",
            "Audits Content Security Policies using Google's official CSP Evaluator engine (v1.1.8) running 100% offline. "
            + "Detects 'unsafe-inline', 'unsafe-eval', missing object-src/base-uri, and identifies known JSONP/Angular allowlist "
            + "bypasses (e.g. cdnjs.cloudflare.com). Includes an interactive Google CSP Scratchpad.",
            "Switch to CSP Inspector",
            () -> mainTabbedPane.setSelectedIndex(5),
            "🌐 Check Google Updates",
            () -> com.littlespidy.headerinspector.csp.evaluator.GoogleCspUpdateChecker.checkForUpdatesAsync(this)
        ));

        cardsGrid.add(createModuleCard(
            "🔒 HSTS Inspector",
            "Evaluates Strict-Transport-Security configurations against RFC 6797 and browser preload criteria. "
            + "Flags missing HSTS, short max-age (< 1 year / < 30 days), max-age=0 opt-outs, and missing includeSubDomains. "
            + "Severity-coded triage table with instant TSV export.",
            "Switch to HSTS Inspector",
            () -> mainTabbedPane.setSelectedIndex(6)
        ));

        content.add(cardsGrid);
        content.add(Box.createVerticalStrut(20));

        // ── 4. Getting Started Workflow ──
        JPanel workflowPanel = new JPanel(new BorderLayout(6, 6));
        workflowPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        workflowPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "🚀 Quick Start Workflow",
            javax.swing.border.TitledBorder.LEFT, javax.swing.border.TitledBorder.TOP,
            new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));

        JTextArea steps = new JTextArea(
            "1. Browse your target application normally through Burp Proxy to capture traffic.\n"
            + "2. Navigate to any tab (Header Collector, Method Collector, Status Collector, Cache, CSP, or HSTS) and click 'Load Proxy History'.\n"
            + "3. All six modules are immediately populated, classified, and grouped in a single non-blocking pass.\n"
            + "4. Click on any method or status code to inspect all associated endpoints, view the exact RFC semantics from http.dev, or deep-link directly into the HTTP Request/Response editors."
        );
        steps.setEditable(false);
        steps.setOpaque(false);
        steps.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        steps.setLineWrap(true);
        steps.setWrapStyleWord(true);
        steps.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        workflowPanel.add(steps, BorderLayout.CENTER);
        content.add(workflowPanel);

        JScrollPane scroll = new JScrollPane(content);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    private JPanel createModuleCard(String title, String description, String buttonLabel, Runnable action) {
        return createModuleCard(title, description, buttonLabel, action, null, null);
    }

    private JPanel createModuleCard(String title, String description, String buttonLabel, Runnable action, String secondaryLabel, Runnable secondaryAction) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(210, 210, 210), 1, true),
            BorderFactory.createEmptyBorder(14, 14, 14, 14)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));

        JTextArea desc = new JTextArea(description);
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));

        JButton btn = new JButton(buttonLabel);
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        btn.addActionListener(e -> {
            if (action != null) action.run();
        });

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        if (secondaryLabel != null && secondaryAction != null) {
            JButton secBtn = new JButton(secondaryLabel);
            secBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            secBtn.addActionListener(e -> secondaryAction.run());
            bottomRow.add(secBtn);
        }
        bottomRow.add(btn);

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(desc, BorderLayout.CENTER);
        card.add(bottomRow, BorderLayout.SOUTH);
        return card;
    }

    public void cleanup() {
        if (cacheTab != null) cacheTab.cleanup();
        if (cspTab != null) cspTab.cleanup();
        if (hstsTab != null) hstsTab.cleanup();
    }
}
