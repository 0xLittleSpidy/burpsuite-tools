// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.activescansessionkeeper.config.CookieMode;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.function.BiConsumer;

/**
 * Modal prompt dialog displayed when an active scan thread detects session expiration.
 * Pauses scan execution, alerts the user, and collects fresh session credentials to resume scanning.
 *
 * @author littlespidy
 */
public class CookiePromptDialog extends JDialog {

    private final SessionKeeperConfig config;
    private final String reason;
    private final String details;
    private final String url;
    private final HttpRequest initiatingRequest;
    private final BiConsumer<String, Boolean> onUpdateCallback;

    private JTextArea cookieInputArea;
    private JRadioButton namedRadio;
    private JRadioButton fullHeaderRadio;
    private JRadioButton bearerRadio;
    private JCheckBox autoRetryCheckbox;

    public CookiePromptDialog(Window parent, SessionKeeperConfig config, String reason, String details,
                              String url, HttpRequest initiatingRequest,
                              BiConsumer<String, Boolean> onUpdateCallback) {
        super(parent, "⚠️ Active Scan Session Expired — Action Required", ModalityType.APPLICATION_MODAL);
        this.config = config;
        this.reason = reason;
        this.details = details;
        this.url = url;
        this.initiatingRequest = initiatingRequest;
        this.onUpdateCallback = onUpdateCallback;

        initComponents();
        setSize(650, 520);
        setLocationRelativeTo(parent);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(8, 8));
        contentPane.setBorder(new EmptyBorder(12, 14, 12, 14));

        // ── 1. Top Banner ───────────────────────────────────────────────────
        JPanel bannerPanel = new JPanel(new BorderLayout(10, 6));
        bannerPanel.setBackground(new Color(254, 243, 199)); // Soft amber
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(245, 158, 11), 1),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        JLabel titleLabel = new JLabel("⚠️ ACTIVE SCAN PAUSED: SESSION EXPIRATION DETECTED!");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        titleLabel.setForeground(new Color(146, 64, 14)); // Dark amber

        JLabel descLabel = new JLabel("<html>The Burp Active Scanner encountered an expiration trigger. "
                + "All scan threads are safely paused waiting for fresh credentials.</html>");
        descLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        descLabel.setForeground(new Color(120, 53, 15));

        bannerPanel.add(titleLabel, BorderLayout.NORTH);
        bannerPanel.add(descLabel, BorderLayout.CENTER);

        // ── 2. Trigger Info Details ─────────────────────────────────────────
        JPanel infoPanel = new JPanel(new GridBagLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Expiration Trigger Diagnostics",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11)
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 6, 3, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel reasonHeader = new JLabel("Trigger Reason:");
        reasonHeader.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        infoPanel.add(reasonHeader, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        JLabel reasonVal = new JLabel("🚨 " + reason);
        reasonVal.setForeground(new Color(185, 28, 28)); // Dark red
        reasonVal.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        infoPanel.add(reasonVal, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        JLabel urlHeader = new JLabel("Target URL:");
        urlHeader.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        infoPanel.add(urlHeader, gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        JTextField urlField = new JTextField(url);
        urlField.setEditable(false);
        urlField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        urlField.setBackground(new Color(243, 244, 246));
        infoPanel.add(urlField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0;
        JLabel detailHeader = new JLabel("Details:");
        detailHeader.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        infoPanel.add(detailHeader, gbc);

        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0;
        JLabel detailVal = new JLabel("<html>" + details + "</html>");
        detailVal.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        infoPanel.add(detailVal, gbc);

        // ── 3. Cookie Input & Mode Selection ────────────────────────────────
        JPanel inputPanel = new JPanel(new BorderLayout(6, 6));
        inputPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Provide Fresh Session Credentials",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11)
        ));

        JPanel modeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        namedRadio = new JRadioButton("Specific Cookie(s) (" + config.getTargetCookieNames() + ")");
        fullHeaderRadio = new JRadioButton("Full Cookie Header");
        bearerRadio = new JRadioButton("Authorization: Bearer");

        ButtonGroup bg = new ButtonGroup();
        bg.add(fullHeaderRadio);
        bg.add(namedRadio);
        bg.add(bearerRadio);

        if (config.getCookieMode() == CookieMode.NAMED_COOKIES) {
            namedRadio.setSelected(true);
        } else if (config.getCookieMode() == CookieMode.AUTHORIZATION_BEARER) {
            bearerRadio.setSelected(true);
        } else {
            fullHeaderRadio.setSelected(true);
        }

        modeRow.add(new JLabel("Mode:"));
        modeRow.add(fullHeaderRadio);
        modeRow.add(namedRadio);
        modeRow.add(bearerRadio);

        inputPanel.add(modeRow, BorderLayout.NORTH);

        cookieInputArea = new JTextArea(5, 40);
        cookieInputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cookieInputArea.setLineWrap(true);
        cookieInputArea.setWrapStyleWord(true);

        // Prepopulate with current or initiating request cookies
        String initialText = "";
        if (config.getCookieMode() == CookieMode.FULL_COOKIE_HEADER && !config.getFullCookieHeader().isEmpty()) {
            initialText = config.getFullCookieHeader();
        } else if (config.getCookieMode() == CookieMode.NAMED_COOKIES && !config.getCookieValue().isEmpty()) {
            initialText = config.getCookieValue();
        } else if (initiatingRequest != null && initiatingRequest.hasHeader("Cookie")) {
            initialText = initiatingRequest.headerValue("Cookie");
        }
        cookieInputArea.setText(initialText);
        cookieInputArea.selectAll();

        JScrollPane scroll = new JScrollPane(cookieInputArea);
        scroll.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));
        inputPanel.add(scroll, BorderLayout.CENTER);

        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        autoRetryCheckbox = new JCheckBox("Automatically re-send failed scan request with this fresh cookie", config.isAutoRetryOnExpire());
        optionsRow.add(autoRetryCheckbox);
        inputPanel.add(optionsRow, BorderLayout.SOUTH);

        // ── Center Compound ──
        JPanel centerPanel = new JPanel(new BorderLayout(6, 6));
        centerPanel.add(infoPanel, BorderLayout.NORTH);
        centerPanel.add(inputPanel, BorderLayout.CENTER);

        // ── 4. Bottom Action Buttons ────────────────────────────────────────
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));

        JButton disableBtn = new JButton("Disable Keeper for this Scan");
        disableBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        disableBtn.addActionListener(e -> {
            config.setEnabled(false);
            dispose();
        });

        JButton ignoreBtn = new JButton("Ignore Once & Resume");
        ignoreBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        ignoreBtn.addActionListener(e -> dispose());

        JButton updateBtn = new JButton("✅ Update Cookie & Resume Scan");
        updateBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        updateBtn.setForeground(new Color(22, 101, 52)); // Dark green
        updateBtn.addActionListener(e -> handleUpdate());

        btnPanel.add(disableBtn);
        btnPanel.add(ignoreBtn);
        btnPanel.add(updateBtn);

        // Layout Assembly
        contentPane.add(bannerPanel, BorderLayout.NORTH);
        contentPane.add(centerPanel, BorderLayout.CENTER);
        contentPane.add(btnPanel, BorderLayout.SOUTH);

        setContentPane(contentPane);
        getRootPane().setDefaultButton(updateBtn);
    }

    private void handleUpdate() {
        String input = cookieInputArea.getText().trim();
        if (input.isEmpty()) {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Cookie input is empty. Resume scan without setting a new cookie?",
                    "Empty Cookie", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
        }

        if (fullHeaderRadio.isSelected()) {
            config.setCookieMode(CookieMode.FULL_COOKIE_HEADER);
            config.setFullCookieHeader(input);
        } else if (namedRadio.isSelected()) {
            config.setCookieMode(CookieMode.NAMED_COOKIES);
            config.setCookieValue(input);
        } else if (bearerRadio.isSelected()) {
            config.setCookieMode(CookieMode.AUTHORIZATION_BEARER);
            config.setAuthBearerToken(input);
        }

        config.setAutoRetryOnExpire(autoRetryCheckbox.isSelected());

        if (onUpdateCallback != null) {
            onUpdateCallback.accept(input, autoRetryCheckbox.isSelected());
        }

        dispose();
    }
}
