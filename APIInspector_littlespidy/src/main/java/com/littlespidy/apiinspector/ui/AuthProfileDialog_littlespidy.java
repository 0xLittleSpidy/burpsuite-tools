// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.AuthType_littlespidy;
import com.littlespidy.apiinspector.util.JwtTokenHelper_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
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
    private JPanel tokenInfoCard;
    private JLabel tokenLengthLabel;
    private JLabel tokenValidityLabel;

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
        setMinimumSize(new Dimension(500, 520));
        setResizable(true);
        setLocationRelativeTo(parent);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(10, 10));
        contentPane.setBorder(new EmptyBorder(12, 12, 12, 12));

        // Form Panel - Clean vertical orientation
        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
        formPanel.setBorder(new TitledBorder("Profile Configuration"));

        // 1. Profile Name (Vertical block)
        JPanel nameBlock = new JPanel(new BorderLayout(4, 4));
        nameBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel nameLabel = new JLabel("Profile Name:");
        nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
        nameBlock.add(nameLabel, BorderLayout.NORTH);
        nameField = new JTextField(28);
        nameBlock.add(nameField, BorderLayout.CENTER);
        formPanel.add(nameBlock);

        formPanel.add(Box.createVerticalStrut(10));

        // 2. Profile Type (Vertical block)
        JPanel typeBlock = new JPanel(new BorderLayout(4, 4));
        typeBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel typeLabel = new JLabel("Profile Type:");
        typeLabel.setFont(typeLabel.getFont().deriveFont(Font.BOLD));
        typeBlock.add(typeLabel, BorderLayout.NORTH);

        JPanel typeRadioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        authRadio = new JRadioButton("Authenticated (auth)", true);
        unauthRadio = new JRadioButton("Unauthenticated (unauth)", false);
        ButtonGroup group = new ButtonGroup();
        group.add(authRadio);
        group.add(unauthRadio);
        typeRadioPanel.add(authRadio);
        typeRadioPanel.add(unauthRadio);
        typeBlock.add(typeRadioPanel, BorderLayout.CENTER);
        formPanel.add(typeBlock);

        authRadio.addActionListener(e -> updateHeadersMode(false));
        unauthRadio.addActionListener(e -> updateHeadersMode(true));

        formPanel.add(Box.createVerticalStrut(10));

        // 3. Headers Section (Vertical tall text area)
        JPanel headersBlock = new JPanel(new BorderLayout(4, 4));
        headersBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        headersLabel = new JLabel("Session Headers (Complete Headers):");
        headersLabel.setFont(headersLabel.getFont().deriveFont(Font.BOLD));
        headersBlock.add(headersLabel, BorderLayout.NORTH);

        headersHelpLabel = new JLabel("Enter complete headers (e.g. 'Authorization: Bearer <token>', 'Cookie: session=<id>'), one per line.");
        headersHelpLabel.setFont(headersHelpLabel.getFont().deriveFont(Font.PLAIN, 11f));
        headersHelpLabel.setForeground(Color.GRAY);

        JPanel headersContainer = new JPanel(new BorderLayout(4, 4));
        headersContainer.add(headersHelpLabel, BorderLayout.NORTH);

        headersArea = new JTextArea(10, 34);
        headersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        headersArea.setLineWrap(true);
        headersArea.setWrapStyleWord(true);
        headersArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateTokenInfo(); }
            @Override public void removeUpdate(DocumentEvent e) { updateTokenInfo(); }
            @Override public void changedUpdate(DocumentEvent e) { updateTokenInfo(); }
        });

        JScrollPane headersScroll = new JScrollPane(headersArea);
        headersScroll.setPreferredSize(new Dimension(440, 180));
        headersContainer.add(headersScroll, BorderLayout.CENTER);

        // Token Info Card (Length and JWT Expiration display)
        tokenInfoCard = new JPanel(new GridLayout(2, 1, 2, 2));
        tokenInfoCard.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Authorization & JWT Token Info"),
                new EmptyBorder(4, 8, 4, 8)
        ));
        tokenLengthLabel = new JLabel("Token Length: -");
        tokenLengthLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        tokenValidityLabel = new JLabel("Validity Status: -");
        tokenValidityLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 11));
        tokenInfoCard.add(tokenLengthLabel);
        tokenInfoCard.add(tokenValidityLabel);
        headersContainer.add(tokenInfoCard, BorderLayout.SOUTH);

        headersBlock.add(headersContainer, BorderLayout.CENTER);
        formPanel.add(headersBlock);

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

    private void updateTokenInfo() {
        if (unauthRadio != null && unauthRadio.isSelected()) {
            if (tokenInfoCard != null) tokenInfoCard.setVisible(false);
            return;
        }
        if (tokenInfoCard != null) tokenInfoCard.setVisible(true);

        String text = headersArea != null ? headersArea.getText() : "";
        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(text);

        if (!info.hasToken()) {
            if (tokenLengthLabel != null) {
                tokenLengthLabel.setText("Token Length: No Authorization token configured");
            }
            if (tokenValidityLabel != null) {
                tokenValidityLabel.setText("Status: Inactive");
                tokenValidityLabel.setForeground(Color.GRAY);
            }
            return;
        }

        if (tokenLengthLabel != null) {
            tokenLengthLabel.setText("Token Length: " + info.tokenLength() + " chars (Header Value: " + info.headerLength() + " chars)");
        }

        if (tokenValidityLabel != null) {
            if (info.isJwt()) {
                if (info.expEpochSecond() != null) {
                    if (info.isExpired()) {
                        tokenValidityLabel.setText("Validity: Expired (" + info.formattedRemainingTime() + " ago | " + info.formattedUtcTime() + ")");
                        tokenValidityLabel.setForeground(new Color(199, 84, 80));
                    } else {
                        tokenValidityLabel.setText("Validity: Active (" + info.formattedRemainingTime() + " remaining | " + info.formattedUtcTime() + ")");
                        tokenValidityLabel.setForeground(new Color(73, 156, 84));
                    }
                } else {
                    tokenValidityLabel.setText("Validity: Active JWT (No exp claim in payload)");
                    tokenValidityLabel.setForeground(new Color(73, 156, 84));
                }
            } else {
                tokenValidityLabel.setText("Validity: Non-JWT Bearer / Custom Token");
                tokenValidityLabel.setForeground(Color.GRAY);
            }
        }
    }

    private void updateHeadersMode(boolean isUnauth) {
        if (isUnauth) {
            headersLabel.setText("Headers to Remove (Header Names):");
            headersHelpLabel.setText("Enter header names to remove (e.g. 'Authorization:', 'Cookie:'), one per line.");
        } else {
            headersLabel.setText("Session Headers (Complete Headers):");
            headersHelpLabel.setText("Enter complete headers (e.g. 'Authorization: Bearer <token>', 'Cookie: session=<id>'), one per line.");
        }
        updateTokenInfo();
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
        updateTokenInfo();
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
