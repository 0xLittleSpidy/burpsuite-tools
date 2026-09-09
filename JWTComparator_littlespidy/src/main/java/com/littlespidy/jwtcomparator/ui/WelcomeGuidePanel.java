// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Onboarding dashboard and documentation tab presenting the workflow methodology,
 * dynamic N-token side-by-side comparison, context menu usage, and triage guidelines.
 */
public class WelcomeGuidePanel extends JPanel {

    private final JWTComparatorTab mainTab;

    public WelcomeGuidePanel() {
        this(null);
    }

    public WelcomeGuidePanel(JWTComparatorTab mainTab) {
        this.mainTab = mainTab;

        setLayout(new BorderLayout(15, 15));
        setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        // Header Panel
        JPanel headerPanel = new JPanel(new BorderLayout(10, 10));

        JPanel titleAndAction = new JPanel(new BorderLayout(10, 5));
        JLabel titleLabel = new JLabel("JWT Comparator");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));

        JButton launchBtn = new JButton("🔍 Open Comparator");
        launchBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        launchBtn.setToolTipText("Switch to interactive JWT comparison tab");
        launchBtn.addActionListener(e -> {
            if (this.mainTab != null) {
                this.mainTab.selectComparatorTab();
            }
        });

        JButton launchAttackerBtn = new JButton("⚔️ Open Token Attacker");
        launchAttackerBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        launchAttackerBtn.setToolTipText("Switch to Token Attacker / Access Matrix replay tab");
        launchAttackerBtn.addActionListener(e -> {
            if (this.mainTab != null) {
                this.mainTab.selectAttackerTab();
            }
        });

        headerButtons.add(launchBtn);
        headerButtons.add(launchAttackerBtn);

        titleAndAction.add(titleLabel, BorderLayout.WEST);
        if (this.mainTab != null) {
            titleAndAction.add(headerButtons, BorderLayout.EAST);
        }

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setText(
                "JWT Comparator is an interactive multi-token diffing and comparison extension for Burp Suite. "
                        + "Designed specifically for modern web application testing and microservice architectures, it lets you "
                        + "seamlessly compare JSON Web Tokens across different domains, services, user roles, and authorization boundaries.\n\n"
                        + "Built on the modern Montoya API with support for dynamic N tokens (side-by-side vertical columns), "
                        + "custom token naming, JSON session export/import, TSV download, on-demand context menu extraction, and color-coded claim diffing."
        );

        headerPanel.add(titleAndAction, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);

        // Modular Tutorial Cards
        JPanel cardsPanel = new JPanel(new GridLayout(0, 2, 18, 18));

        cardsPanel.add(createCard(
                "1. Multi-Domain & Cross-Service Comparison",
                "Applications frequently issue different JWT tokens for different domains or microservices "
                        + "(e.g., auth.example.com, api.orders.corp, internal.service.net). Easily inspect cross-domain isolation, "
                        + "audience scoping ('aud'), issuer validity ('iss'), and potential token replay vulnerabilities."
        ));

        cardsPanel.add(createCard(
                "2. Side-by-Side Vertical Columns (Left to Right)",
                "Compare 2, 3, 4, or more tokens simultaneously. Token slots are structured as side-by-side vertical "
                        + "columns arranged from left to right with smooth horizontal scrolling. Click '➕ Add Another Token Slot' "
                        + "to dynamically append additional token columns."
        ));

        cardsPanel.add(createCard(
                "3. Custom Token Naming",
                "Explicitly name each token slot using the 'Name:' input field (e.g. 'Admin Prod', 'Staging User', 'Domain A'). "
                        + "Token names update the comparison matrix columns, selected claim inspector tabs, and TSV reports in real time."
        ));

        cardsPanel.add(createCard(
                "4. Session JSON Save & Import",
                "Save your entire working token set and labels with '💾 Export JSON' to a structured JSON file. "
                        + "Load saved sessions anytime using '📂 Import JSON' to resume multi-environment security reviews without re-pasting."
        ));

        cardsPanel.add(createCard(
                "5. Right-Click 'Send to JWT Comparator'",
                "Right-click any HTTP request or response in Burp (Proxy, Repeater, Logger) to instantly send tokens to the comparator. "
                        + "The extension automatically detects and extracts JWTs from 'Authorization: Bearer', cookie headers, "
                        + "request/response bodies, or text selections, pre-populating host domains and opening the comparator tab."
        ));

        cardsPanel.add(createCard(
                "6. Instant Claims Diffing & Status Highlights",
                "All header parameters and payload claims are unified into a color-coded matrix:\n"
                        + " • Amber: Value Mismatches (values differ across tokens).\n"
                        + " • Soft Red: Partially Missing (claims present in some tokens but absent in others).\n"
                        + " • Neutral: Identical matches across all tokens."
        ));

        cardsPanel.add(createCard(
                "7. Epoch Timestamp & Expiration Inspector",
                "Automatically translates Unix epoch timestamps ('exp', 'iat', 'nbf', 'auth_time') into human-readable UTC "
                        + "and Local dates, calculating remaining lifetime or elapsed expiration time."
        ));

        cardsPanel.add(createCard(
                "8. TSV Download & Clipboard Export",
                "Download the entire comparison matrix directly as a file ('💾 Download TSV') or copy it to the clipboard "
                        + "('📋 Copy TSV') for fast reporting, team documentation, and bug bounty proof-of-concept sharing."
        ));

        cardsPanel.add(createCard(
                "9. Ignore Claims in Differences View",
                "Filter out expected noise such as timestamps ('exp', 'iat', 'nbf', 'auth_time') or dynamic IDs ('jti') "
                        + "from the 'Differences Only' view. Configure via the 'Ignore:' toolbar box, click '⚙️' for preset "
                        + "toggles, or right-click any row in the matrix to ignore/unignore that claim on demand."
        ));

        cardsPanel.add(createCard(
                "10. Token Attacker (Replay & Access Matrix)",
                "Send one or multiple HTTP requests directly to the 'Token Attacker' tab (via right-click '⚔️ Send Request to Token Attacker' "
                        + "in Burp Proxy, Repeater, or Logger). Click '🚀 Start Attack' to replay all requests across all loaded JWT tokens "
                        + "and an unauthenticated baseline. The extension maps the responses into a color-coded Access Matrix to detect "
                        + "BOLA / IDOR, broken authorization boundaries, and unauthenticated endpoints."
        ));

        JPanel container = new JPanel(new BorderLayout(15, 15));
        container.add(headerPanel, BorderLayout.NORTH);
        container.add(cardsPanel, BorderLayout.CENTER);

        JScrollPane scrollPane = new JScrollPane(container);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createCard(String title, String description) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Separator.foreground") != null ?
                        UIManager.getColor("Separator.foreground") : new Color(200, 200, 200), 1, true),
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

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(desc, BorderLayout.CENTER);
        return card;
    }
}
