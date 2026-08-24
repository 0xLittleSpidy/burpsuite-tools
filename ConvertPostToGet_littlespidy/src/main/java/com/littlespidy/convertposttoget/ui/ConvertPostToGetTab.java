package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import com.littlespidy.convertposttoget.model.PostCandidate;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import java.awt.*;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Top-level suite tab supporting welcome guide, POST Traffic Discovery,
 * and dynamically spawned conversion session tabs with close buttons.
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

        PostCandidate candidate = new PostCandidate(
            1,
            request.method(),
            request.url(),
            request.httpService() != null ? request.httpService().host() : "",
            urlPath,
            response != null ? response.statusCode() : 0,
            response != null ? response.body().length() : 0,
            response != null && response.headerValue("Content-Type") != null ? response.headerValue("Content-Type") : "",
            request.parameters().size(),
            Collections.emptyList(),
            false,
            "None",
            dedupeKey,
            request,
            response,
            ZonedDateTime.now()
        );

        addNewBatchSessionTab(List.of(candidate));
    }

    public void addNewBatchSessionTab(List<PostCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) return;

        String title;
        if (candidates.size() == 1) {
            PostCandidate single = candidates.get(0);
            String path = single.path();
            if (path == null || path.isEmpty()) path = "/";
            title = single.method() + " " + (path.length() > 22 ? path.substring(0, 22) + "..." : path);
        } else {
            title = "Attack (" + candidates.size() + " targets)";
        }

        ConvertSessionPanel sessionPanel = new ConvertSessionPanel(
            api,
            config,
            candidates,
            this::closeSession
        );

        activeSessions.add(sessionPanel);
        rootTabbedPane.addTab(title, sessionPanel);
        int tabIndex = rootTabbedPane.indexOfComponent(sessionPanel);

        // ── Custom Tab Header with Close Button ──
        JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabHeader.setOpaque(false);
        JLabel titleLabel = new JLabel(title);

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
            + "2. Filter endpoints by parameter names (e.g. action, csrf, id, token) or status codes.\n"
            + "3. Select target candidates with checkboxes [x] and click 'Attack'.\n"
            + "4. In the session tab, optionally inject fresh session cookies, Bearer tokens, or API keys using 'Custom Headers & Auth...'.\n"
            + "5. Click 'Start Conversion Test' and inspect findings in the comparative results table."
        );

        JPanel contentPanel = new JPanel(new GridLayout(0, 2, 16, 16));

        JPanel card1 = createFeatureCard(
            "Body Parameter Migration",
            "Converts URL-encoded form data, JSON top-level keys, and multipart bodies into URL query parameters."
        );
        JPanel card2 = createFeatureCard(
            "Fresh Auth / Session Injection",
            "Easily inject updated session cookies, Bearer tokens, or API keys when testing captured traffic at the end of an assessment."
        );
        JPanel card3 = createFeatureCard(
            "Signal & Bypass Detection",
            "Flags 403->200 Authorization/WAF bypasses, 200->200 Method Permitted / CSRF risks, and 5xx crashes."
        );
        JPanel card4 = createFeatureCard(
            "Burp Active Scanner Integration",
            "Also registered as an active ScanCheck, automatically converting POST requests to GET during Burp active audits."
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
