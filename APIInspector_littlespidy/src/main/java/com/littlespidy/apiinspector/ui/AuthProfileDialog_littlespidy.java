// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.ApiKeyLocation_littlespidy;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.AuthType_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Modal dialog for creating and editing authentication profiles.
 * Provides dynamically switched input forms for Bearer token, API Key,
 * Basic Auth, Cookie, and Custom Header credentials with masked secret inputs.
 */
public class AuthProfileDialog_littlespidy extends JDialog {

    private final AuthProfile_littlespidy profile;
    private boolean confirmed = false;

    private JTextField nameField;
    private JComboBox<AuthType_littlespidy> authTypeCombo;

    // Card Layout container for mechanism fields
    private JPanel cardPanel;
    private CardLayout cardLayout;

    // Bearer
    private JPasswordField bearerTokenField;
    private JToggleButton bearerShowBtn;

    // API Key
    private JTextField apiKeyNameField;
    private JPasswordField apiKeyValueField;
    private JComboBox<ApiKeyLocation_littlespidy> apiKeyLocCombo;
    private JToggleButton apiKeyShowBtn;

    // Basic
    private JTextField basicUsernameField;
    private JPasswordField basicPasswordField;
    private JToggleButton basicShowBtn;

    // Cookie
    private JTextField cookieNameField;
    private JPasswordField cookieValueField;
    private JToggleButton cookieShowBtn;

    // Custom Header
    private JTextField customHeaderNameField;
    private JPasswordField customHeaderValueField;
    private JToggleButton customShowBtn;

    public AuthProfileDialog_littlespidy(Window parent, String title, AuthProfile_littlespidy initialProfile) {
        super(parent, title, ModalityType.APPLICATION_MODAL);
        this.profile = initialProfile != null ? initialProfile : new AuthProfile_littlespidy();

        initComponents();
        populateFields();
        pack();
        setResizable(false);
        setLocationRelativeTo(parent);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(10, 10));
        contentPane.setBorder(new EmptyBorder(12, 12, 12, 12));

        // Top Form: Name, Mechanism, Unauth Checkbox
        JPanel topForm = new JPanel(new GridBagLayout());
        topForm.setBorder(new TitledBorder("General Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        topForm.add(new JLabel("Profile Name:"), gbc);
        nameField = new JTextField(24);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        topForm.add(nameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        topForm.add(new JLabel("Auth Mechanism:"), gbc);
        authTypeCombo = new JComboBox<>(AuthType_littlespidy.values());
        authTypeCombo.addActionListener(e -> {
            AuthType_littlespidy sel = (AuthType_littlespidy) authTypeCombo.getSelectedItem();
            if (sel != null && cardLayout != null) {
                cardLayout.show(cardPanel, sel.name());
            }
        });
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        topForm.add(authTypeCombo, gbc);



        contentPane.add(topForm, BorderLayout.NORTH);

        // Center: Cards for credentials
        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);
        cardPanel.setBorder(new TitledBorder("Credentials & Headers"));

        // 1. Bearer Token Card
        cardPanel.add(createBearerCard(), AuthType_littlespidy.BEARER_TOKEN.name());
        // 2. API Key Card
        cardPanel.add(createApiKeyCard(), AuthType_littlespidy.API_KEY.name());
        // 3. Basic Auth Card
        cardPanel.add(createBasicCard(), AuthType_littlespidy.BASIC_AUTH.name());
        // 4. Cookie Card
        cardPanel.add(createCookieCard(), AuthType_littlespidy.COOKIE.name());
        // 5. Custom Header Card
        cardPanel.add(createCustomHeaderCard(), AuthType_littlespidy.CUSTOM_HEADER.name());

        contentPane.add(cardPanel, BorderLayout.CENTER);

        // Bottom: Action Buttons
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

    private JPanel createBearerCard() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        p.add(new JLabel("Bearer Token:"), gbc);

        bearerTokenField = new JPasswordField(24);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        p.add(bearerTokenField, gbc);

        bearerShowBtn = createMaskToggleButton(bearerTokenField);
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        p.add(bearerShowBtn, gbc);

        return p;
    }

    private JPanel createApiKeyCard() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        p.add(new JLabel("Key Name:"), gbc);
        apiKeyNameField = new JTextField("X-API-Key", 20);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; gbc.gridwidth = 2;
        p.add(apiKeyNameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0; gbc.gridwidth = 1;
        p.add(new JLabel("Key Value:"), gbc);
        apiKeyValueField = new JPasswordField(20);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        p.add(apiKeyValueField, gbc);
        apiKeyShowBtn = createMaskToggleButton(apiKeyValueField);
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        p.add(apiKeyShowBtn, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        p.add(new JLabel("Key Location:"), gbc);
        apiKeyLocCombo = new JComboBox<>(ApiKeyLocation_littlespidy.values());
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0; gbc.gridwidth = 2;
        p.add(apiKeyLocCombo, gbc);

        return p;
    }

    private JPanel createBasicCard() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        p.add(new JLabel("Username:"), gbc);
        basicUsernameField = new JTextField(20);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; gbc.gridwidth = 2;
        p.add(basicUsernameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0; gbc.gridwidth = 1;
        p.add(new JLabel("Password:"), gbc);
        basicPasswordField = new JPasswordField(20);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        p.add(basicPasswordField, gbc);
        basicShowBtn = createMaskToggleButton(basicPasswordField);
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        p.add(basicShowBtn, gbc);

        return p;
    }

    private JPanel createCookieCard() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        p.add(new JLabel("Cookie Name:"), gbc);
        cookieNameField = new JTextField("sessionid", 20);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; gbc.gridwidth = 2;
        p.add(cookieNameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0; gbc.gridwidth = 1;
        p.add(new JLabel("Cookie Value:"), gbc);
        cookieValueField = new JPasswordField(20);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        p.add(cookieValueField, gbc);
        cookieShowBtn = createMaskToggleButton(cookieValueField);
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        p.add(cookieShowBtn, gbc);

        return p;
    }

    private JPanel createCustomHeaderCard() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        p.add(new JLabel("Header Name:"), gbc);
        customHeaderNameField = new JTextField("X-Custom-Auth", 20);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; gbc.gridwidth = 2;
        p.add(customHeaderNameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0; gbc.gridwidth = 1;
        p.add(new JLabel("Header Value:"), gbc);
        customHeaderValueField = new JPasswordField(20);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        p.add(customHeaderValueField, gbc);
        customShowBtn = createMaskToggleButton(customHeaderValueField);
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        p.add(customShowBtn, gbc);

        return p;
    }

    private JToggleButton createMaskToggleButton(JPasswordField pwdField) {
        JToggleButton btn = new JToggleButton("Show");
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 11f));
        btn.addActionListener(e -> {
            if (btn.isSelected()) {
                pwdField.setEchoChar((char) 0);
                btn.setText("Hide");
            } else {
                pwdField.setEchoChar('\u2022');
                btn.setText("Show");
            }
        });
        return btn;
    }

    private void populateFields() {
        nameField.setText(profile.getName());
        authTypeCombo.setSelectedItem(profile.getAuthType());

        bearerTokenField.setText(profile.getBearerToken());

        apiKeyNameField.setText(profile.getApiKeyName());
        apiKeyValueField.setText(profile.getApiKeyValue());
        apiKeyLocCombo.setSelectedItem(profile.getApiKeyLocation());

        basicUsernameField.setText(profile.getBasicUsername());
        basicPasswordField.setText(profile.getBasicPassword());

        cookieNameField.setText(profile.getCookieName());
        cookieValueField.setText(profile.getCookieValue());

        customHeaderNameField.setText(profile.getCustomHeaderName());
        customHeaderValueField.setText(profile.getCustomHeaderValue());

        cardLayout.show(cardPanel, profile.getAuthType().name());
    }

    private void onSave() {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Profile name cannot be empty.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        profile.setName(name);
        AuthType_littlespidy selType = (AuthType_littlespidy) authTypeCombo.getSelectedItem();
        profile.setAuthType(selType != null ? selType : AuthType_littlespidy.BEARER_TOKEN);

        profile.setBearerToken(new String(bearerTokenField.getPassword()).trim());

        profile.setApiKeyName(apiKeyNameField.getText().trim());
        profile.setApiKeyValue(new String(apiKeyValueField.getPassword()).trim());
        ApiKeyLocation_littlespidy loc = (ApiKeyLocation_littlespidy) apiKeyLocCombo.getSelectedItem();
        profile.setApiKeyLocation(loc != null ? loc : ApiKeyLocation_littlespidy.HEADER);

        profile.setBasicUsername(basicUsernameField.getText().trim());
        profile.setBasicPassword(new String(basicPasswordField.getPassword()).trim());

        profile.setCookieName(cookieNameField.getText().trim());
        profile.setCookieValue(new String(cookieValueField.getPassword()).trim());

        profile.setCustomHeaderName(customHeaderNameField.getText().trim());
        profile.setCustomHeaderValue(new String(customHeaderValueField.getPassword()).trim());

        confirmed = true;
        dispose();
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public AuthProfile_littlespidy getProfile() {
        return profile;
    }
}
