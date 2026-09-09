// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Onboarding dashboard and documentation tab presenting the workflow methodology,
 * dynamic N-token comparison, context menu usage, and triage guidelines.
 */
public class WelcomeGuidePanel extends JPanel {

    public WelcomeGuidePanel() {
        setLayout(new BorderLayout(15, 15));
        setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        // Header Panel
        JPanel headerPanel = new JPanel(new BorderLayout(5, 10));

        JLabel titleLabel = new JLabel("JWT Comparator");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

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
                        + "Built on the modern Montoya API with support for dynamic N tokens, on-demand context menu extraction, and color-coded claim diffing."
        );

        headerPanel.add(titleLabel, BorderLayout.NORTH);
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
                "2. Dynamic N-Token Comparison Matrix",
                "Compare 2, 3, 4, or more tokens simultaneously. Click '➕ Add Another Token Slot' to add dynamic token cards. "
                        + "Customize domain labels (e.g. 'Prod Admin', 'Staging User') directly on the card to keep track of environments and roles."
        ));

        cardsPanel.add(createCard(
                "3. Right-Click 'Send to JWT Comparator'",
                "Right-click any HTTP request or response in Burp (Proxy, Repeater, Logger) to instantly send tokens to the comparator. "
                        + "The extension automatically detects and extracts JWTs from 'Authorization: Bearer', cookie headers, "
                        + "request/response bodies, or text selections, and pre-populates the host domain as the label."
        ));

        cardsPanel.add(createCard(
                "4. Instant Claims Diffing & Status Highlights",
                "All header parameters and payload claims are unified into a color-coded matrix:\n"
                        + " • Amber: Value Mismatches (values differ across tokens).\n"
                        + " • Soft Red: Partially Missing (claims present in some tokens but absent in others).\n"
                        + " • Neutral: Identical matches across all tokens."
        ));

        cardsPanel.add(createCard(
                "5. 'Differences Only' Focused Auditing",
                "Toggle the View filter from 'All Claims' to 'Differences Only' to immediately eliminate noise and "
                        + "isolate divergence in user roles, scopes, permissions, tenants, or algorithms."
        ));

        cardsPanel.add(createCard(
                "6. Epoch Timestamp & Expiration Inspector",
                "Automatically translates Unix epoch timestamps ('exp', 'iat', 'nbf', 'auth_time') into human-readable UTC "
                        + "and Local dates, calculating remaining lifetime or elapsed expiration time."
        ));

        cardsPanel.add(createCard(
                "7. Detailed Claim Inspector & Decoded Viewers",
                "Select any claim row in the matrix to inspect complex nested JSON objects or arrays in dedicated per-token tabs. "
                        + "Click '🔍 View Decoded' on any token card for full pretty-printed JSON of Header and Payload."
        ));

        cardsPanel.add(createCard(
                "8. One-Click TSV Export & Reporting",
                "Click '📋 Copy TSV Diff' to copy the entire comparison matrix to the clipboard for fast reporting, "
                        + "documentation, and bug bounty proof-of-concept sharing."
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
