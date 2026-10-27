// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.AuthType_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.function.Consumer;

/**
 * Modeless dialog for creating and editing authentication profiles.
 * Allows entering raw session headers for Authenticated profiles or specifying
 * header names to strip for Unauthenticated profiles.
 */
public class AuthProfileDialog_littlespidy extends JDialog {

    private final AuthProfile_littlespidy profile;
    private final Consumer<AuthProfile_littlespidy> onSaveCallback;
    private boolean confirmed = false;

    private JTextField nameField;
    private JRadioButton authRadio;
    private JRadioButton unauthRadio;
    private JLabel headersLabel;
    private JLabel headersHelpLabel;
    private JTextArea headersArea;

    public AuthProfileDialog_littlespidy(Window parent, String title, AuthProfile_littlespidy initialProfile) {
        this(parent, title, initialProfile, null);
    }

    public AuthProfileDialog_littlespidy(Window parent, String title, AuthProfile_littlespidy initialProfile, Consumer<AuthProfile_littlespidy> onSaveCallback) {
        super(parent, title, ModalityType.MODELESS);
        this.profile = initialProfile != null ? initialProfile : new AuthProfile_littlespidy();
        this.onSaveCallback = onSaveCallback;

        initComponents();
        populateFields();
        pack();
        setResizable(true);
        setLocationRelativeTo(parent);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(10, 10));
        contentPane.setBorder(new EmptyBorder(12, 12, 12, 12));

        // Form Panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(new TitledBorder("Profile Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Profile Name
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        formPanel.add(new JLabel("Profile Name:"), gbc);
        nameField = new JTextField(24);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        formPanel.add(nameField, gbc);

        // Profile Type: Auth vs Unauth Radio buttons
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        formPanel.add(new JLabel("Profile Type:"), gbc);

        JPanel typePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        authRadio = new JRadioButton("Authenticated (auth)", true);
        unauthRadio = new JRadioButton("Unauthenticated (unauth)", false);
        ButtonGroup group = new ButtonGroup();
        group.add(authRadio);
        group.add(unauthRadio);
        typePanel.add(authRadio);
        typePanel.add(unauthRadio);

        authRadio.addActionListener(e -> updateHeadersMode(false));
        unauthRadio.addActionListener(e -> updateHeadersMode(true));

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        formPanel.add(typePanel, gbc);

        // Headers Section
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        headersLabel = new JLabel("Session Headers (Complete Headers):");
        headersLabel.setFont(headersLabel.getFont().deriveFont(Font.BOLD));
        formPanel.add(headersLabel, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        headersHelpLabel = new JLabel("Enter complete headers (e.g. 'Authorization: Bearer <token>', 'Cookie: session=<id>'), one per line.");
        headersHelpLabel.setFont(headersHelpLabel.getFont().deriveFont(Font.PLAIN, 11f));
        headersHelpLabel.setForeground(Color.GRAY);
        formPanel.add(headersHelpLabel, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        headersArea = new JTextArea(8, 30);
        headersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane headersScroll = new JScrollPane(headersArea);
        headersScroll.setPreferredSize(new Dimension(380, 160));
        formPanel.add(headersScroll, gbc);

        contentPane.add(formPanel, BorderLayout.CENTER);

        // Bottom Button Panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        JButton saveBtn = new JButton("Save Profile");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> onSave());

        buttonPanel.add(cancelBtn);
        buttonPanel.add(saveBtn);
        contentPane.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(contentPane);
    }

    private void updateHeadersMode(boolean isUnauth) {
        if (isUnauth) {
            headersLabel.setText("Headers to Remove (Header Names):");
            headersHelpLabel.setText("Enter header names to remove (e.g. 'Authorization:', 'Cookie:'), one per line.");
        } else {
            headersLabel.setText("Session Headers (Complete Headers):");
            headersHelpLabel.setText("Enter complete headers (e.g. 'Authorization: Bearer <token>', 'Cookie: session=<id>'), one per line.");
        }
    }

    private void populateFields() {
        nameField.setText(profile.getName());
        boolean isUnauth = profile.isUnauthenticated();
        authRadio.setSelected(!isUnauth);
        unauthRadio.setSelected(isUnauth);
        updateHeadersMode(isUnauth);

        if (profile.getRawHeaders() != null && !profile.getRawHeaders().isBlank()) {
            headersArea.setText(profile.getRawHeaders());
        } else if (!isUnauth) {
            // Populate from existing fields if rawHeaders is not set yet
            StringBuilder sb = new StringBuilder();
            if (!profile.getBearerToken().isBlank()) {
                sb.append("Authorization: Bearer ").append(profile.getBearerToken()).append("\n");
            }
            if (!profile.getCookieValue().isBlank()) {
                sb.append("Cookie: ").append(profile.getCookieName()).append("=").append(profile.getCookieValue()).append("\n");
            }
            if (!profile.getCustomHeaderValue().isBlank()) {
                sb.append(profile.getCustomHeaderName()).append(": ").append(profile.getCustomHeaderValue()).append("\n");
            }
            headersArea.setText(sb.toString().trim());
        } else {
            headersArea.setText("Authorization:\nCookie:");
        }
    }

    private void onSave() {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Profile name cannot be empty.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        profile.setName(name);
        boolean isUnauth = unauthRadio.isSelected();
        profile.setUnauthenticated(isUnauth);
        String raw = headersArea.getText().trim();
        profile.setRawHeaders(raw);

        // Sync helper fields for backward compatibility
        if (!isUnauth && !raw.isEmpty()) {
            String[] lines = raw.split("[\\r\\n]+");
            for (String line : lines) {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    String hName = line.substring(0, colon).trim();
                    String hVal = line.substring(colon + 1).trim();
                    if (hName.equalsIgnoreCase("Authorization")) {
                        if (hVal.toLowerCase().startsWith("bearer ")) {
                            profile.setAuthType(AuthType_littlespidy.BEARER_TOKEN);
                            profile.setBearerToken(hVal.substring(7).trim());
                        } else {
                            profile.setAuthType(AuthType_littlespidy.CUSTOM_HEADER);
                            profile.setCustomHeaderName(hName);
                            profile.setCustomHeaderValue(hVal);
                        }
                    } else if (hName.equalsIgnoreCase("Cookie")) {
                        profile.setAuthType(AuthType_littlespidy.COOKIE);
                        int eq = hVal.indexOf('=');
                        if (eq > 0) {
                            profile.setCookieName(hVal.substring(0, eq).trim());
                            profile.setCookieValue(hVal.substring(eq + 1).trim());
                        }
                    }
                }
            }
        }

        confirmed = true;
        if (onSaveCallback != null) {
            onSaveCallback.accept(profile);
        }
        dispose();
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public AuthProfile_littlespidy getProfile() {
        return profile;
    }
}
