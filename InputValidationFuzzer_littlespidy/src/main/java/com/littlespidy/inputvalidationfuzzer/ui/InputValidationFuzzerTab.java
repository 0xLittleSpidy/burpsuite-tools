package com.littlespidy.inputvalidationfuzzer.ui;

import com.littlespidy.inputvalidationfuzzer.model.FuzzerConfig;
import com.littlespidy.inputvalidationfuzzer.model.TrafficCandidate;
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
 * Top-level suite tab supporting welcome/onboarding guides, Traffic Sweep & Discovery,
 * and dynamically spawned fuzzing session tabs (single or multi-target batch) with close buttons.
 *
 * @author littlespidy
 */
public class InputValidationFuzzerTab extends JPanel {
    private final MontoyaApi api;
    private final FuzzerConfig config;
    private final JTabbedPane rootTabbedPane = new JTabbedPane();
    private final List<FuzzingSessionPanel> activeSessions = new ArrayList<>();
    private final TrafficSweepPanel trafficSweepPanel;

    public InputValidationFuzzerTab(MontoyaApi api, FuzzerConfig config) {
        this.api = api;
        this.config = config;

        setLayout(new BorderLayout());
        rootTabbedPane.addTab("Welcome & Guide", createWelcomePanel());

        this.trafficSweepPanel = new TrafficSweepPanel(api, config, this::addNewBatchSessionTab);
        rootTabbedPane.addTab("Traffic Sweep & Discovery", trafficSweepPanel);

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void addNewSessionTab(HttpRequest request, HttpResponse response) {
        String urlPath = request.path();
        if (urlPath == null || urlPath.isEmpty()) urlPath = "/";
        String dedupeKey = request.method() + "|" + request.url();

        TrafficCandidate candidate = new TrafficCandidate(
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

    public void addNewBatchSessionTab(List<TrafficCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) return;

        String title;
        if (candidates.size() == 1) {
            TrafficCandidate single = candidates.get(0);
            String path = single.path();
            if (path == null || path.isEmpty()) path = "/";
            title = single.method() + " " + (path.length() > 22 ? path.substring(0, 22) + "..." : path);
        } else {
            title = "Attack (" + candidates.size() + " targets)";
        }

        FuzzingSessionPanel sessionPanel = new FuzzingSessionPanel(
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

    private void closeSession(FuzzingSessionPanel session) {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "Are you sure you want to close this fuzzing session?",
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

        JLabel titleLabel = new JLabel("Input Validation Fuzzer");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setText(
            "Input Validation Fuzzer actively injects edge-case values, special characters, null bytes, "
            + "and boundary integers into request parameters to uncover improper input handling, verbose error leaks, "
            + "unhandled exceptions, and injection flaws.\n\n"
            + "How to use:\n"
            + "1. Switch to 'Traffic Sweep & Discovery' and click 'Load from Proxy History'.\n"
            + "2. Filter parameter-bearing endpoints using method, status, or comma-separated parameter names.\n"
            + "3. Select target candidates with checkboxes [x] (or click 'Select All').\n"
            + "4. Click 'Attack' to spawn a dedicated fuzzing session tab.\n"
            + "5. In the session tab, click 'Start Fuzzing' to run tests, inspect findings in the results table, and use the filter sidebar in real time."
        );

        JPanel contentPanel = new JPanel(new GridLayout(0, 2, 16, 16));

        JPanel card1 = createFeatureCard(
            "Targeted Parameter Fuzzing",
            "Fuzzes URL Query, Body (Form), JSON, XML, and Multipart parameters while ignoring non-parameter elements (Cookies opt-in)."
        );
        JPanel card2 = createFeatureCard(
            "Multi-Signal Detection",
            "Identifies 5xx server errors, 30+ error signatures (SQL/Java/PHP exceptions), unencoded payload reflections, and response size anomalies."
        );
        JPanel card3 = createFeatureCard(
            "Burp Active Scanner Integration",
            "Also registered as an active ScanCheck, running automatically during Burp active audits with scanner deduplication."
        );
        JPanel card4 = createFeatureCard(
            "Smart & Manual Filtering",
            "Suppresses repetitive response signatures automatically and enables real-time status code, regex, and severity filtering."
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
        for (FuzzingSessionPanel session : activeSessions) {
            session.cleanup();
        }
        activeSessions.clear();
    }
}
