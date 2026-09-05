// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Onboarding dashboard and documentation tab presenting the workflow methodology,
 * detection rules, domain filtering, live progress bar, deep-linking quad, and triage guidelines.
 */
public class WelcomeGuidePanel extends JPanel {

    public WelcomeGuidePanel() {
        setLayout(new BorderLayout(15, 15));
        setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        // Header
        JPanel headerPanel = new JPanel(new BorderLayout(5, 10));

        JLabel titleLabel = new JLabel("Response Inspector");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setText(
                "Response Inspector is an interactive auditing and triage extension for Burp Suite designed to analyze "
                        + "HTTP responses for exposed credentials, personal identifiable information (PII), server infrastructure paths, "
                        + "database exceptions, runtime stack traces, and cloud API secrets.\n\n"
                        + "Built on the modern Montoya API with a zero-freeze, on-demand processing architecture."
        );

        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);

        // Modular Tutorial Cards
        JPanel cardsPanel = new JPanel(new GridLayout(0, 2, 18, 18));

        cardsPanel.add(createCard(
                "1. On-Demand Ingestion & Live Progress Bar",
                "Traffic is ingested deterministically via 'Load Proxy History' without continuous background listener overhead. "
                        + "A dedicated live progress strip displays real-time item counts (e.g. 'Scanning 450/2100 items') along with "
                        + "an auto-hiding determinate JProgressBar that guarantees safe UI state recovery."
        ));

        cardsPanel.add(createCard(
                "2. Granular In-Scope Domain Selection",
                "Burp's target scope is often broad. Click 'In-Scope Domains...' to select or deselect specific hosts "
                        + "(e.g. target api.example.com while ignoring cdn.example.com or third-party scopes). "
                        + "All four category tables update instantly based on your chosen domains."
        ));

        cardsPanel.add(createCard(
                "3. Auto-Navigation & Deep-Linking Quad",
                "Selecting any finding row automatically: (1) auto-switches the editor to the Response/Request sub-tab; "
                        + "(2) applies native Montoya Markers painting yellow/orange highlight boxes over the match; "
                        + "(3) populates Burp's editor search bar expression; and (4) auto-scrolls the viewport directly to the line."
        ));

        cardsPanel.add(createCard(
                "4. Targeted Password Auditing",
                "Click 'Configure Passwords... (N active)' on the Passwords tab to paste known target credentials, user passwords, "
                        + "or wordlists. Responses (bodies, Set-Cookie, auth headers) are scanned for these exact credentials "
                        + "with zero speculative false-positives."
        ));

        cardsPanel.add(createCard(
                "5. Strict SSN & OS Server Filesystem Paths",
                "Validates US Social Security Numbers (\b\\d{3}-\\d{2}-\\d{4}\b) against invalid area/group/serial rules "
                        + "(excluding 000-, 666-, 900-999-, and repeating dummy numbers). Real OS server filesystem paths "
                        + "(/etc/, /var/log/, C:\\inetpub\\, UNC shares) are discovered while standard web URL routes are ignored."
        ));

        cardsPanel.add(createCard(
                "6. Database Leaks & Server Errors",
                "Ported from DetectHTTPResponseErrors_littlespidy.bambda. Uncovers leaked database syntax errors "
                        + "(MySQL, PostgreSQL, Oracle, MSSQL, SQLite, DB2, MongoDB, LDAP) and runtime stack traces "
                        + "(PHP, Java, Python, Ruby, Go panics, Node.js, Django, Hibernate, ASP.NET)."
        ));

        cardsPanel.add(createCard(
                "7. Secrets, Cloud Keys & Tokens",
                "Ported from sensitive-discoverer. Audits responses for exposed AWS keys, Google API keys, GitHub tokens, "
                        + "Slack webhooks/tokens, Stripe keys, Twilio/SendGrid, RSA/EC private keys, JWTs, and .env leaks. "
                        + "Matched tokens are safely masked in the table."
        ));

        cardsPanel.add(createCard(
                "8. Multi-Select Triage Filters",
                "Filter findings instantly using MultiSelectFilterButton popups for HTTP Method (GET, POST, etc.), "
                        + "Status Code (2xx, 3xx, 4xx, 5xx, 200, 302, 403, 500), and Content-Type (JSON, HTML, JavaScript, XML). "
                        + "Select multiple values at once without clearing other filter criteria."
        ));

        cardsPanel.add(createCard(
                "9. Inter-Tool Actions & Row Pinning",
                "Right-click any row to 'Send to Repeater' (with METHOD host/path tab titles), 'Send to Intruder', "
                        + "'Send to Organizer', or 'Copy Match Excerpt'. Use 'Pin Selected' to isolate specific findings "
                        + "independent of general filters, and press Ctrl+C / Cmd+C for instant TSV clipboard export."
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
                BorderFactory.createLineBorder(new Color(200, 200, 200), 1, true),
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
