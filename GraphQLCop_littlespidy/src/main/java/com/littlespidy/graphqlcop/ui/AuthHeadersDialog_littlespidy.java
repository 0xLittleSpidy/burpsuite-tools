// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class AuthHeadersDialog_littlespidy extends JDialog {
    private final JTextArea headersTextArea;
    private boolean saved = false;

    public AuthHeadersDialog_littlespidy(Window owner, String initialHeaders) {
        super(owner, "Configure Session & Authentication Headers", ModalityType.APPLICATION_MODAL);
        setLayout(new BorderLayout(8, 8));
        setSize(560, 380);
        setLocationRelativeTo(owner);

        JPanel contentPanel = new JPanel(new BorderLayout(6, 6));
        contentPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        JLabel infoLabel = new JLabel("<html><b>Enter Custom Headers for Outgoing Probes & Audits</b><br>" +
                "<span style='color:gray;'>Specify one header per line in 'Header-Name: Value' format (e.g. Authorization, X-API-Key, Cookie).<br>" +
                "Standard Burp / browser User-Agent is preserved without override.</span></html>");
        contentPanel.add(infoLabel, BorderLayout.NORTH);

        headersTextArea = new JTextArea();
        headersTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        headersTextArea.setText(initialHeaders != null ? initialHeaders : "");
        JScrollPane scrollPane = new JScrollPane(headersTextArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("HTTP Headers"));
        contentPanel.add(scrollPane, BorderLayout.CENTER);

        add(contentPanel, BorderLayout.CENTER);

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton saveBtn = new JButton("Save Headers");
        JButton cancelBtn = new JButton("Cancel");

        saveBtn.addActionListener(e -> {
            saved = true;
            dispose();
        });
        cancelBtn.addActionListener(e -> {
            saved = false;
            dispose();
        });

        buttonBar.add(saveBtn);
        buttonBar.add(cancelBtn);
        add(buttonBar, BorderLayout.SOUTH);
    }

    public boolean isSaved() {
        return saved;
    }

    public String getHeadersText() {
        return headersTextArea.getText().trim();
    }
}
