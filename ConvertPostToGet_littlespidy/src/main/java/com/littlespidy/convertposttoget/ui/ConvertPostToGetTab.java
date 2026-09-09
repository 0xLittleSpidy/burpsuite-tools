// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import com.littlespidy.convertposttoget.model.PostCandidate;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import java.awt.*;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Top-level suite tab supporting welcome guide, POST Traffic Discovery with Core Four filters,
 * and dynamically spawned conversion session tabs with close buttons and live ambient glyphs.
 *
 * Follows extension_architecture.md standards.
 *
 * @author littlespidy
 */
public class ConvertPostToGetTab extends JPanel {
    private final MontoyaApi api;
    private final ConvertPostToGetConfig config;
    private final JTabbedPane rootTabbedPane = new JTabbedPane();
    private final List<ConvertSessionPanel> activeSessions = new ArrayList<>();
    private final PostTrafficSweepPanel postTrafficSweepPanel;

    public ConvertPostToGetTab(MontoyaApi api, ConvertPostToGetConfig config) {
        this.api = api;
        this.config = config;

        setLayout(new BorderLayout());
        rootTabbedPane.addTab("Welcome & Guide", createWelcomePanel());

        this.postTrafficSweepPanel = new PostTrafficSweepPanel(api, config, this::addNewBatchSessionTab);
        rootTabbedPane.addTab("POST Traffic Discovery", postTrafficSweepPanel);

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void addNewSessionTab(HttpRequest request, HttpResponse response) {
        String urlPath = request.path();
        if (urlPath == null || urlPath.isEmpty()) urlPath = "/";
        String dedupeKey = request.method() + "|" + request.url();

        Set<String> paramTypes = new HashSet<>();
        List<String> paramNames = new ArrayList<>();
        for (ParsedHttpParameter p : request.parameters()) {
            if (p.type() != HttpParameterType.COOKIE) {
                paramNames.add(p.name());
                if (p.type() == HttpParameterType.BODY) paramTypes.add("BODY");
                else if (p.type() == HttpParameterType.URL) paramTypes.add("URL");
                else if (p.type() == HttpParameterType.JSON) paramTypes.add("JSON");
                else if (p.type() == HttpParameterType.MULTIPART_ATTRIBUTE) paramTypes.add("MULTIPART");
                else if (p.type() == HttpParameterType.XML || p.type() == HttpParameterType.XML_ATTRIBUTE) paramTypes.add("XML");
            }
        }

        String cType = request.headerValue("Content-Type");
        if (cType != null) {
            String lower = cType.toLowerCase();
            if (lower.contains("json")) paramTypes.add("JSON");
            if (lower.contains("form-urlencoded")) paramTypes.add("BODY");
            if (lower.contains("multipart")) paramTypes.add("MULTIPART");
            if (lower.contains("xml")) paramTypes.add("XML");
        }

        boolean isAuth = request.headerValue("Authorization") != null || request.headerValue("Cookie") != null;
        String authLabel = request.headerValue("Authorization") != null ? "Authorization Header" : (request.headerValue("Cookie") != null ? "Cookie" : "None");

        PostCandidate candidate = new PostCandidate(
            1,
            request.method(),
            request.url(),
            request.httpService() != null ? request.httpService().host() : "",
            urlPath,
            response != null ? response.statusCode() : 0,
            response != null ? response.body().length() : 0,
            response != null && response.headerValue("Content-Type") != null ? response.headerValue("Content-Type") : (cType != null ? cType : ""),
            paramNames.size(),
            paramNames,
            paramTypes,
            isAuth,
            authLabel,
            dedupeKey,
            request,
            response,
            ZonedDateTime.now()
        );

        addNewBatchSessionTab(List.of(candidate));
    }

    public void addNewBatchSessionTab(List<PostCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) return;

        String baseTitle;
        if (candidates.size() == 1) {
            PostCandidate single = candidates.get(0);
            String path = single.path();
            if (path == null || path.isEmpty()) path = "/";
            baseTitle = single.method() + " " + (path.length() > 22 ? path.substring(0, 22) + "..." : path);
        } else {
            baseTitle = "Attack (" + candidates.size() + " targets)";
        }

        ConvertSessionPanel sessionPanel = new ConvertSessionPanel(
            api,
            config,
            candidates,
            this::closeSession
        );

        activeSessions.add(sessionPanel);
        rootTabbedPane.addTab(baseTitle, sessionPanel);
        int tabIndex = rootTabbedPane.indexOfComponent(sessionPanel);

        // ── Custom Tab Header with Close Button and Live Ambient Status Glyphs ──
        JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabHeader.setOpaque(false);
        JLabel titleLabel = new JLabel(baseTitle);

        // Wire ambient status glyph on session completion per extension_architecture.md
        sessionPanel.setCompletionGlyphCallback(findingsCount -> {
            SwingUtilities.invokeLater(() -> {
                String glyph = findingsCount > 0 ? "⚠️" : "✔";
                titleLabel.setText(glyph + " " + baseTitle);
            });
        });

        JButton closeBtn = new JButton("×");
        closeBtn.setMargin(new Insets(0, 4, 0, 4));
        closeBtn.setBorder(BorderFactory.createEmptyBorder());
        closeBtn.setContentAreaFilled(false);
        closeBtn.setFocusable(false);
        closeBtn.setToolTipText("Close this session");
        closeBtn.addActionListener(e -> closeSession(sessionPanel));

        tabHeader.add(titleLabel);
        tabHeader.add(closeBtn);
        rootTabbedPane.setTabComponentAt(tabIndex, tabHeader);

        rootTabbedPane.setSelectedComponent(sessionPanel);
    }

    private void closeSession(ConvertSessionPanel session) {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "Are you sure you want to close this conversion session?",
            "Close Session",
            JOptionPane.YES_NO_OPTION
        );

        if (confirm == JOptionPane.YES_OPTION) {
            session.cleanup();
            activeSessions.remove(session);
            rootTabbedPane.remove(session);
        }
    }

    private JPanel createWelcomePanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        JLabel titleLabel = new JLabel("Convert POST to GET");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setText(
            "Convert POST to GET tests whether state-changing, access-controlled, or WAF-protected POST endpoints "
            + "can be executed via HTTP GET requests by migrating request body parameters into the URL query string.\n\n"
            + "Why this matters:\n"
            + "• CSRF Defense Evasion: Applications often validate CSRF tokens or SameSite cookie rules only on POST requests.\n"
            + "• WAF / ACL Bypass: Web Application Firewalls or authorization middleware may only restrict the POST verb.\n"
            + "• Method Confusion: Many backend frameworks (PHP, Spring, Express, Django) automatically bind query parameters into controller handlers.\n\n"
            + "How to use:\n"
            + "1. Switch to 'POST Traffic Discovery' and click 'Load from Proxy History'.\n"
            + "2. Use the Core Triage Filters (Domain, Multi-Select Status, Content-Type, Param Types, In-Scope, and Regex Search) to isolate target endpoints.\n"
            + "3. Select candidates with checkboxes [x] (or 'Pin Selected') and click '\u26A1 Attack'.\n"
            + "4. In the session tab, inject fresh auth tokens via 'Custom Headers & Auth...' if needed, then run conversion tests.\n"
            + "5. Leverage the Collapsible Smart Filter Sidebar (500px) and Deep-Linking Quad in Montoya editors to triage findings."
        );

        JPanel contentPanel = new JPanel(new GridLayout(0, 2, 16, 16));

        JPanel card1 = createFeatureCard(
            "Core Four Triage Filtering",
            "MultiSelectFilterButtons for Status, Content-Type, and Parameter Types, non-destructive In-Scope gating, and sanitized domain matching."
        );
        JPanel card2 = createFeatureCard(
            "Smart Pattern Suppression & Presets",
            "Collapsible 500px results sidebar auto-suppresses repeated generic signatures and provides 1-click presets for bypasses and CSRF."
        );
        JPanel card3 = createFeatureCard(
            "4-Pillar Deep-Linking Quad",
            "Auto-tab switching, native Montoya marker highlighting, search bar populating, and auto-scrolled viewports center directly on findings."
        );
        JPanel card4 = createFeatureCard(
            "Burp Suite Interoperability",
            "Right-click context menu integration for Send to Repeater, Intruder, and Organizer, plus row pinning and live status glyphs (⚠️ / ✔)."
        );

        contentPanel.add(card1);
        contentPanel.add(card2);
        contentPanel.add(card3);
        contentPanel.add(card4);

        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);

        panel.add(headerPanel, BorderLayout.NORTH);
        panel.add(contentPanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createFeatureCard(String title, String description) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(210, 210, 210), 1),
            BorderFactory.createEmptyBorder(12, 12, 12, 12)
        ));

        JLabel tLabel = new JLabel(title);
        tLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));

        JTextArea dArea = new JTextArea(description);
        dArea.setEditable(false);
        dArea.setOpaque(false);
        dArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        dArea.setLineWrap(true);
        dArea.setWrapStyleWord(true);

        card.add(tLabel, BorderLayout.NORTH);
        card.add(dArea, BorderLayout.CENTER);
        return card;
    }

    public void cleanupAll() {
        for (ConvertSessionPanel session : activeSessions) {
            session.cleanup();
        }
        activeSessions.clear();
    }
}
