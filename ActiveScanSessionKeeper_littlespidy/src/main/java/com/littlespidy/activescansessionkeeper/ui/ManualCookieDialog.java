// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.ui;

import com.littlespidy.activescansessionkeeper.config.CookieMode;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Dialog allowing users to manually inspect, edit, or paste active session credentials.
 *
 * @author littlespidy
 */
public class ManualCookieDialog extends JDialog {

    private final SessionKeeperConfig config;
    private JTextArea cookieArea;
    private JRadioButton namedRadio;
    private JRadioButton fullHeaderRadio;
    private JRadioButton bearerRadio;

    public ManualCookieDialog(Window parent, SessionKeeperConfig config) {
        super(parent, "🍪 Configure Active Scan Session Cookie", ModalityType.APPLICATION_MODAL);
        this.config = config;

        initComponents();
        setSize(580, 420);
        setLocationRelativeTo(parent);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(8, 8));
        contentPane.setBorder(new EmptyBorder(12, 14, 12, 14));

        JLabel title = new JLabel("Configure Session Credentials for Active Scan");
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        contentPane.add(title, BorderLayout.NORTH);

        JPanel centerPanel = new JPanel(new BorderLayout(6, 6));

        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        modePanel.setBorder(BorderFactory.createTitledBorder("Credential Injection Mode"));

        fullHeaderRadio = new JRadioButton("Full Cookie Header");
        namedRadio = new JRadioButton("Named Cookie Value");
        bearerRadio = new JRadioButton("Authorization: Bearer Token");

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

        modePanel.add(fullHeaderRadio);
        modePanel.add(namedRadio);
        modePanel.add(bearerRadio);
        centerPanel.add(modePanel, BorderLayout.NORTH);

        JPanel inputPanel = new JPanel(new BorderLayout(4, 4));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Cookie / Token Content"));

        cookieArea = new JTextArea(8, 40);
        cookieArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cookieArea.setLineWrap(true);
        cookieArea.setWrapStyleWord(true);

        if (config.getCookieMode() == CookieMode.FULL_COOKIE_HEADER) {
            cookieArea.setText(config.getFullCookieHeader());
        } else if (config.getCookieMode() == CookieMode.NAMED_COOKIES) {
            cookieArea.setText(config.getCookieValue());
        } else {
            cookieArea.setText(config.getAuthBearerToken());
        }

        inputPanel.add(new JScrollPane(cookieArea), BorderLayout.CENTER);
        centerPanel.add(inputPanel, BorderLayout.CENTER);

        contentPane.add(centerPanel, BorderLayout.CENTER);

        // Buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = new JButton("Save Credentials");
        saveBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        saveBtn.addActionListener(e -> {
            String val = cookieArea.getText().trim();
            if (fullHeaderRadio.isSelected()) {
                config.setCookieMode(CookieMode.FULL_COOKIE_HEADER);
                config.setFullCookieHeader(val);
            } else if (namedRadio.isSelected()) {
                config.setCookieMode(CookieMode.NAMED_COOKIES);
                config.setCookieValue(val);
            } else {
                config.setCookieMode(CookieMode.AUTHORIZATION_BEARER);
                config.setAuthBearerToken(val);
            }
            dispose();
        });

        btnPanel.add(cancelBtn);
        btnPanel.add(saveBtn);
        contentPane.add(btnPanel, BorderLayout.SOUTH);

        setContentPane(contentPane);
        getRootPane().setDefaultButton(saveBtn);
    }
}
