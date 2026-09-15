// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Interactive Google CSP Evaluator Scratchpad dialog allowing testers to paste,
 * edit, and evaluate arbitrary CSP headers directly within Burp Suite without leaving to a browser.
 *
 * @author littlespidy
 */
public class GoogleCspScratchpadDialog extends JDialog {

    private final JTextArea inputTextArea = new JTextArea(4, 50);
    private final GoogleCspEvaluatorPanel evaluatorPanel = new GoogleCspEvaluatorPanel();

    private static final String[] PRESET_NAMES = {
        "-- Select an Example Template --",
        "Example 1: Angular Allowlist Bypass (cdnjs)",
        "Example 2: JSONP Allowlist Bypass (googleapis)",
        "Example 3: Vulnerable 'unsafe-inline' & Wildcard",
        "Example 4: Missing object-src & base-uri",
        "Example 5: Google Strict CSP with Nonce (Secure)",
        "Example 6: Missing Semicolon Syntax Error"
    };

    private static final String[] PRESET_POLICIES = {
        "",
        "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; object-src 'none';",
        "default-src 'self'; script-src 'self' https://www.googleapis.com 'unsafe-eval'; object-src 'none';",
        "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'; object-src *;",
        "script-src 'self' 'nonce-abcdef123456'; style-src 'self';",
        "default-src 'none'; script-src 'nonce-rAnd0m123' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script';",
        "script-src 'self' object-src 'none' style-src 'self'"
    };

    public GoogleCspScratchpadDialog(Window parent, String initialPolicy) {
        super(parent, "🧪 Google CSP Evaluator Scratchpad", ModalityType.MODELESS);
        setLayout(new BorderLayout(8, 8));
        setSize(920, 680);
        setLocationRelativeTo(parent);

        initComponents(initialPolicy);
    }

    private void initComponents(String initialPolicy) {
        JPanel mainPanel = new JPanel(new BorderLayout(8, 8));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ── Top: Input Editor & Toolbar ──
        JPanel topContainer = new JPanel(new BorderLayout(6, 6));

        JPanel headerBar = new JPanel(new BorderLayout(6, 6));
        JLabel titleLabel = new JLabel("Paste or Edit Content Security Policy (CSP):");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));

        JComboBox<String> presetCombo = new JComboBox<>(PRESET_NAMES);
        presetCombo.addActionListener(e -> {
            int idx = presetCombo.getSelectedIndex();
            if (idx > 0 && idx < PRESET_POLICIES.length) {
                inputTextArea.setText(PRESET_POLICIES[idx]);
                evaluate();
            }
        });

        headerBar.add(titleLabel, BorderLayout.WEST);
        headerBar.add(presetCombo, BorderLayout.EAST);

        inputTextArea.setLineWrap(true);
        inputTextArea.setWrapStyleWord(true);
        inputTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        if (initialPolicy != null && !initialPolicy.isBlank()) {
            inputTextArea.setText(initialPolicy);
        } else {
            inputTextArea.setText("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; object-src 'none';");
        }

        JScrollPane inputScroll = new JScrollPane(inputTextArea);
        inputScroll.setPreferredSize(new Dimension(800, 90));

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton evalBtn = new JButton("▶ Evaluate with Google Engine");
        evalBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        evalBtn.addActionListener(e -> evaluate());

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            inputTextArea.setText("");
            presetCombo.setSelectedIndex(0);
            evaluatorPanel.setPolicy("");
        });

        JButton checkUpdatesBtn = new JButton("🌐 Check Google Updates");
        checkUpdatesBtn.setToolTipText("Check for new releases from https://github.com/google/csp-evaluator");
        checkUpdatesBtn.addActionListener(e -> com.littlespidy.headerinspector.csp.evaluator.GoogleCspUpdateChecker.checkForUpdatesAsync(this));

        buttonBar.add(evalBtn);
        buttonBar.add(clearBtn);
        buttonBar.add(checkUpdatesBtn);

        topContainer.add(headerBar, BorderLayout.NORTH);
        topContainer.add(inputScroll, BorderLayout.CENTER);
        topContainer.add(buttonBar, BorderLayout.SOUTH);

        mainPanel.add(topContainer, BorderLayout.NORTH);
        mainPanel.add(evaluatorPanel, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);

        // Run initial evaluation
        evaluate();
    }

    private void evaluate() {
        String policy = inputTextArea.getText().trim();
        evaluatorPanel.setPolicy(policy);
    }
}
