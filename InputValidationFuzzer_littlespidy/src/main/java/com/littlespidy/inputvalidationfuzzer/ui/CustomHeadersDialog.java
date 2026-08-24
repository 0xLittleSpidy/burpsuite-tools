package com.littlespidy.inputvalidationfuzzer.ui;

import com.littlespidy.inputvalidationfuzzer.model.ConfiguredHeader;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Modal dialog for configuring custom session cookies, Authorization tokens,
 * and API keys to inject into fuzzing requests.
 *
 * @author littlespidy
 */
public class CustomHeadersDialog extends JDialog {
    private final JTextArea headersTextArea = new JTextArea();
    private final Consumer<List<ConfiguredHeader>> saveCallback;

    public CustomHeadersDialog(Frame owner, List<ConfiguredHeader> existingHeaders, Consumer<List<ConfiguredHeader>> saveCallback) {
        super(owner, "Custom Headers & Session Auth Tokens", true);
        this.saveCallback = saveCallback;

        setLayout(new BorderLayout(10, 10));
        setSize(650, 480);
        setLocationRelativeTo(owner);

        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 12, 5, 12));
        JLabel titleLabel = new JLabel("Configure Session Cookies, Authorization Tokens & API Keys");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        JLabel descLabel = new JLabel("<html>Enter one header per line in <code>Header-Name: value</code> format. These headers will be automatically applied to both baseline requests and all fuzzing mutation probes.</html>");
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descLabel, BorderLayout.CENTER);
        add(headerPanel, BorderLayout.NORTH);

        StringBuilder sb = new StringBuilder();
        if (existingHeaders != null) {
            for (ConfiguredHeader h : existingHeaders) {
                sb.append(h.name()).append(": ").append(h.value()).append("\n");
            }
        }
        headersTextArea.setText(sb.toString());
        headersTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        add(new JScrollPane(headersTextArea), BorderLayout.CENTER);

        JPanel presetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        presetPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        JButton addBearerBtn = new JButton("+ Add Bearer Token");
        addBearerBtn.addActionListener(e -> appendHeaderSnippet("Authorization: Bearer <your_jwt_or_token_here>"));
        JButton addCookieBtn = new JButton("+ Add Session Cookie");
        addCookieBtn.addActionListener(e -> appendHeaderSnippet("Cookie: session=<session_id_here>; auth_token=<token>"));
        JButton addApiKeyBtn = new JButton("+ Add X-API-Key");
        addApiKeyBtn.addActionListener(e -> appendHeaderSnippet("X-API-Key: <your_api_key_here>"));

        presetPanel.add(addBearerBtn);
        presetPanel.add(addCookieBtn);
        presetPanel.add(addApiKeyBtn);

        JPanel bottomContainer = new JPanel(new BorderLayout());
        bottomContainer.add(presetPanel, BorderLayout.NORTH);

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.addActionListener(e -> {
            List<ConfiguredHeader> parsed = new ArrayList<>();
            for (String line : headersTextArea.getText().split("\n")) {
                ConfiguredHeader h = ConfiguredHeader.parse(line);
                if (h != null) {
                    parsed.add(h);
                }
            }
            saveCallback.accept(parsed);
            dispose();
        });

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        actionPanel.add(saveBtn);
        actionPanel.add(cancelBtn);
        bottomContainer.add(actionPanel, BorderLayout.SOUTH);

        add(bottomContainer, BorderLayout.SOUTH);
    }

    private void appendHeaderSnippet(String snippet) {
        String current = headersTextArea.getText().trim();
        if (current.isEmpty()) {
            headersTextArea.setText(snippet + "\n");
        } else {
            headersTextArea.setText(current + "\n" + snippet + "\n");
        }
    }
}
