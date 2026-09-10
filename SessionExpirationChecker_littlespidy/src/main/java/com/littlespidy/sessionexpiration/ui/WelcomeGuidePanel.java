// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Onboarding dashboard and documentation tab presenting the session expiration
 * testing methodology, baseline cookie matching, milestone timers, and triage workflow.
 *
 * @author littlespidy
 */
public class WelcomeGuidePanel extends JPanel {

    private final SessionExpirationTab mainTab;

    public WelcomeGuidePanel(SessionExpirationTab mainTab) {
        this.mainTab = mainTab;

        setLayout(new BorderLayout(15, 15));
        setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        // ── Header Panel ────────────────────────────────────────────────────
        JPanel headerPanel = new JPanel(new BorderLayout(10, 10));

        JPanel titleAndAction = new JPanel(new BorderLayout(10, 5));
        JLabel titleLabel = new JLabel("⏱️ Session Expiration Checker");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton launchBtn = new JButton("⏱️ Open Session Monitor");
        launchBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        launchBtn.setToolTipText("Switch to active session tracking and timer monitoring tab");
        launchBtn.addActionListener(e -> {
            if (this.mainTab != null) {
                this.mainTab.selectMonitorTab();
            }
        });
        headerButtons.add(launchBtn);

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
                "Session Expiration Checker is an automated session management testing extension for Burp Suite. "
                        + "Designed specifically for modern web application assessments (OWASP ASVS & WSTG-SESS-07), "
                        + "it allows security testers to capture authenticated requests with session cookies/tokens and schedule "
                        + "precision probes across custom milestone intervals (e.g., 15m, 30m, 1h, 3h, 8h) without manual intervention.\n\n"
                        + "Built on the modern Montoya API with daemon background executors, real-time countdown tickers, "
                        + "baseline comparison heuristics, auto-cancellation upon expiration, and native Montoya HTTP editors."
        );

        headerPanel.add(titleAndAction, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);

        // ── Modular Tutorial Cards ──────────────────────────────────────────
        JPanel cardsPanel = new JPanel(new GridLayout(0, 2, 18, 18));

        cardsPanel.add(createCard(
                "1. Session Expiration Testing Methodology",
                "Applications must enforce both idle session timeouts (terminating sessions after periods of inactivity, "
                        + "typically 15–30 minutes) and absolute session limits (e.g. 8–12 hours). This extension supports "
                        + "testing both: idle timeouts by probing after silent intervals, or absolute timeouts by determining "
                        + "whether active tokens are eventually revoked by the server."
        ));

        cardsPanel.add(createCard(
                "2. Baseline Cookie & Request Tracking",
                "When a session request is submitted, the extension captures a baseline with your active cookies and "
                        + "authorization headers. It records the baseline HTTP status code, response body length, and headers. "
                        + "All subsequent milestone probes are matched against this baseline to detect session termination."
        ));

        cardsPanel.add(createCard(
                "3. Staged Milestones from T0 (T0 + Δ)",
                "Configure multiple custom milestone intervals relative to creation time (T0), such as +15m, +30m, +1h, "
                        + "+2h, +3h, +8h, +24h or arbitrary values. Milestones execute automatically in background daemon "
                        + "executors without blocking Burp Suite's UI or freezing the Event Dispatch Thread (EDT)."
        ));

        cardsPanel.add(createCard(
                "4. Heuristic Expiration Detection Engine",
                "Each probe response is evaluated against the baseline using multi-factor heuristics:\n"
                        + " • Status shifts: 200 OK -> 401 Unauthorized, 403 Forbidden, or 3xx redirects.\n"
                        + " • Auth redirects: Location headers pointing to /login, /signin, auth, or SSO.\n"
                        + " • Set-Cookie invalidation: Headers with 'Max-Age=0' or epoch dates (1970).\n"
                        + " • Response body keywords: Signatures like 'session expired' or 'please log in'."
        ));

        cardsPanel.add(createCard(
                "5. Auto-Cancellation on Expiry",
                "As soon as a probe confirms that the session has expired, the extension immediately halts and cancels "
                        + "all remaining scheduled milestone timers for that request. This conserves bandwidth, avoids "
                        + "unnecessary traffic to the target, and pinpoints the exact time window when the session expired."
        ));

        cardsPanel.add(createCard(
                "6. Real-Time Dynamic Countdowns & Master-Detail Triage",
                "The Session Monitor table features a 1-second live countdown ticker showing the time remaining until "
                        + "the next probe (e.g. '29m 14s (30m)'). Selecting a session reveals its milestone history table, "
                        + "probe request, probe response, and baseline response in built-in Montoya Pretty/Raw/Hex editors."
        ));

        cardsPanel.add(createCard(
                "7. Burp Suite Interoperability & Context Menus",
                "Right-click any request in Burp Proxy, Repeater, Logger, or Scanner and choose '⏱️ Send to Session "
                        + "Expiration Checker'. In the extension tables, right-click any row to send requests directly "
                        + "to Repeater ('METHOD host/path'), Intruder, or Organizer."
        ));

        cardsPanel.add(createCard(
                "8. On-Demand Controls & Baseline Refresh",
                "Need to verify a session immediately without waiting for the timer? Right-click and select '▶️ Run "
                        + "Probe Now'. You can also re-send the request to update the baseline with '🔄 Refresh Baseline' "
                        + "or reconfigure milestone intervals anytime via '⏱️ Configure Timers...'."
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
