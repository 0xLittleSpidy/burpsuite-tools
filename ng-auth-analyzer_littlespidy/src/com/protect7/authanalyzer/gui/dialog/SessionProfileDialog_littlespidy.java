// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.dialog;

import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.util.JwtTokenHelper_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.function.Consumer;

/**
 * Modeless dialog for configuring authentication session profiles in ng-auth-analyzer.
 * Compact profile pattern mirroring APIInspector Auth Analyzer.
 */
public class SessionProfileDialog_littlespidy extends JDialog {

    private final SessionPanel sessionPanel;
    private final Consumer<SessionPanel> onSaveCallback;
    private boolean confirmed = false;

    private JTextField nameField;
    private JRadioButton authRadio;
    private JRadioButton unauthRadio;
    private JLabel headersLabel;
    private JTextArea headersArea;
    private JPanel tokenInfoCard;
    private JLabel tokenLengthLabel;
    private JLabel tokenValidityLabel;
    private JCheckBox filterSameHeaderCheckBox;
    private JCheckBox restrictScopeCheckBox;
    private JTextField scopeTextField;
    private JButton matchAndReplaceBtn;
    private JButton addParamBtn;

    public SessionProfileDialog_littlespidy(Window parent, String title, SessionPanel sessionPanel, Consumer<SessionPanel> onSaveCallback) {
        super(parent, title, ModalityType.APPLICATION_MODAL);
        this.sessionPanel = sessionPanel;
        this.onSaveCallback = onSaveCallback;

        initComponents();
        populateFields();
        pack();
        setMinimumSize(new Dimension(520, 500));
        setResizable(true);
        setLocationRelativeTo(parent);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(10, 10));
        contentPane.setBorder(new EmptyBorder(12, 12, 12, 12));

        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
        formPanel.setBorder(new TitledBorder("Profile Configuration"));

        // 1. Profile Name
        JPanel nameBlock = new JPanel(new BorderLayout(4, 4));
        nameBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel nameLabel = new JLabel("Profile Name:");
        nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
        nameBlock.add(nameLabel, BorderLayout.NORTH);
        nameField = new JTextField(28);
        nameBlock.add(nameField, BorderLayout.CENTER);
        formPanel.add(nameBlock);

        formPanel.add(Box.createVerticalStrut(10));

        // 2. Profile Type
        JPanel typeBlock = new JPanel(new BorderLayout(4, 4));
        typeBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel typeLabel = new JLabel("Profile Type:");
        typeLabel.setFont(typeLabel.getFont().deriveFont(Font.BOLD));
        typeBlock.add(typeLabel, BorderLayout.NORTH);

        JPanel typeRadioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        authRadio = new JRadioButton("Authenticated (Replace Headers)", true);
        unauthRadio = new JRadioButton("Unauthenticated (Remove Headers)", false);
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

        // 3. Headers Section
        JPanel headersBlock = new JPanel(new BorderLayout(4, 4));
        headersBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        headersLabel = new JLabel("Headers to Replace (e.g. Cookie or Authorization):");
        headersLabel.setFont(headersLabel.getFont().deriveFont(Font.BOLD));
        headersBlock.add(headersLabel, BorderLayout.NORTH);

        headersArea = new JTextArea(5, 40);
        headersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        headersArea.setLineWrap(true);
        headersArea.setWrapStyleWord(true);
        headersArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateTokenInfo(); }
            @Override public void removeUpdate(DocumentEvent e) { updateTokenInfo(); }
            @Override public void changedUpdate(DocumentEvent e) { updateTokenInfo(); }
        });

        JScrollPane headersScroll = new JScrollPane(headersArea);
        headersScroll.setPreferredSize(new Dimension(460, 100));
        headersBlock.add(headersScroll, BorderLayout.CENTER);

        // 4. Token Length & Remaining Validity Info Card
        tokenInfoCard = new JPanel(new GridLayout(2, 1, 2, 2));
        tokenInfoCard.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(100, 100, 100), 1),
                new EmptyBorder(4, 6, 4, 6)
        ));
        tokenLengthLabel = new JLabel("Character Length: 0 chars");
        tokenLengthLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        tokenValidityLabel = new JLabel("Remaining Validity: No token configured");
        tokenValidityLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        tokenInfoCard.add(tokenLengthLabel);
        tokenInfoCard.add(tokenValidityLabel);
        headersBlock.add(tokenInfoCard, BorderLayout.SOUTH);

        formPanel.add(headersBlock);

        formPanel.add(Box.createVerticalStrut(10));

        // 5. Additional Options
        JPanel optionsBlock = new JPanel(new GridLayout(3, 1, 4, 4));
        optionsBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        filterSameHeaderCheckBox = new JCheckBox("Filter requests having identical header(s)", false);
        restrictScopeCheckBox = new JCheckBox("Restrict analysis to specific Scope / Path", false);
        scopeTextField = new JTextField("https://target.domain/api/");
        scopeTextField.setEnabled(false);
        restrictScopeCheckBox.addActionListener(e -> scopeTextField.setEnabled(restrictScopeCheckBox.isSelected()));

        optionsBlock.add(filterSameHeaderCheckBox);
        JPanel scopeRow = new JPanel(new BorderLayout(4, 0));
        scopeRow.add(restrictScopeCheckBox, BorderLayout.WEST);
        scopeRow.add(scopeTextField, BorderLayout.CENTER);
        optionsBlock.add(scopeRow);

        JPanel extraActionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        matchAndReplaceBtn = new JButton("Match and Replace");
        matchAndReplaceBtn.addActionListener(e -> {
            if (sessionPanel != null) {
                new MatchAndReplaceDialog(sessionPanel);
            }
        });
        addParamBtn = new JButton("Add Parameter");
        addParamBtn.addActionListener(e -> {
            if (sessionPanel != null) {
                sessionPanel.addToken();
                JOptionPane.showMessageDialog(this, "Parameter extraction rule added.", "Parameter Added", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        extraActionsRow.add(matchAndReplaceBtn);
        extraActionsRow.add(addParamBtn);
        optionsBlock.add(extraActionsRow);

        formPanel.add(optionsBlock);

        contentPane.add(formPanel, BorderLayout.CENTER);

        // Bottom Actions
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton saveBtn = new JButton("Save Profile");
        saveBtn.addActionListener(e -> onSave());
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> onCancel());

        bottomBar.add(saveBtn);
        bottomBar.add(cancelBtn);
        contentPane.add(bottomBar, BorderLayout.SOUTH);

        setContentPane(contentPane);
    }

    private void updateHeadersMode(boolean unauth) {
        if (unauth) {
            headersLabel.setText("Headers to Remove (e.g. Cookie: or Authorization:):");
            tokenInfoCard.setVisible(false);
        } else {
            headersLabel.setText("Headers to Replace (e.g. Cookie or Authorization):");
            tokenInfoCard.setVisible(true);
            updateTokenInfo();
        }
    }

    private void updateTokenInfo() {
        if (unauthRadio.isSelected()) {
            tokenInfoCard.setVisible(false);
            return;
        }
        tokenInfoCard.setVisible(true);
        String raw = headersArea.getText();
        if (raw == null || raw.trim().isEmpty()) {
            tokenLengthLabel.setText("Character Length: 0 chars");
            tokenValidityLabel.setText("Remaining Validity: No token configured");
            return;
        }

        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(raw);
        if (!info.hasToken()) {
            tokenLengthLabel.setText("Character Length: " + raw.length() + " chars (raw text)");
            tokenValidityLabel.setText("Remaining Validity: No token detected");
            return;
        }

        tokenLengthLabel.setText("Character Length: " + info.tokenLength() + " chars" +
                (info.isJwt() ? " (JWT payload verified)" : " (Opaque / Non-JWT token)"));

        if (!info.isJwt()) {
            tokenValidityLabel.setText("Remaining Validity: N/A (Non-JWT token)");
        } else if (info.expEpochSecond() == null) {
            tokenValidityLabel.setText("Remaining Validity: No exp claim found in JWT");
        } else if (info.isExpired()) {
            tokenValidityLabel.setText("Remaining Validity: [EXPIRED] " + info.formattedRemainingTime() +
                    " (" + info.formattedUtcTime() + ")");
        } else {
            tokenValidityLabel.setText("Remaining Validity: " + info.formattedRemainingTime() +
                    " (Expires " + info.formattedUtcTime() + ")");
        }
    }

    private void populateFields() {
        if (sessionPanel != null) {
            nameField.setText(sessionPanel.getSessionName());
            boolean isRemove = sessionPanel.isRemoveHeaders();
            if (isRemove) {
                unauthRadio.setSelected(true);
                headersArea.setText(sessionPanel.getHeadersToRemoveText());
            } else {
                authRadio.setSelected(true);
                headersArea.setText(sessionPanel.getHeadersToReplaceText());
            }
            filterSameHeaderCheckBox.setSelected(sessionPanel.isFilterRequestsWithSameHeader());
            restrictScopeCheckBox.setSelected(sessionPanel.isRestrictToScope());
            scopeTextField.setText(sessionPanel.getRestrictToScopeText());
            scopeTextField.setEnabled(sessionPanel.isRestrictToScope());
            updateHeadersMode(isRemove);
        } else {
            nameField.setText("New Profile");
            authRadio.setSelected(true);
            updateHeadersMode(false);
        }
    }

    private void onSave() {
        String name = nameField.getText() != null ? nameField.getText().trim() : "";
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Profile name cannot be empty.", "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (sessionPanel != null) {
            sessionPanel.setSessionName(name);
            boolean isRemove = unauthRadio.isSelected();
            sessionPanel.setRemoveHeaders(isRemove);
            if (isRemove) {
                sessionPanel.setHeadersToRemoveText(headersArea.getText());
            } else {
                sessionPanel.setHeadersToReplaceText(headersArea.getText());
            }
            sessionPanel.setFilterRequestsWithSameHeader(filterSameHeaderCheckBox.isSelected());
            sessionPanel.setRestrictToScope(restrictScopeCheckBox.isSelected());
            if (restrictScopeCheckBox.isSelected()) {
                sessionPanel.setRestrictToScopeText(scopeTextField.getText());
            }
        }

        confirmed = true;
        if (onSaveCallback != null) {
            onSaveCallback.accept(sessionPanel);
        }
        dispose();
    }

    private void onCancel() {
        dispose();
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public String getProfileName() {
        return nameField.getText() != null ? nameField.getText().trim() : "";
    }

    public boolean isRemoveHeaders() {
        return unauthRadio.isSelected();
    }

    public String getHeadersText() {
        return headersArea.getText();
    }

    public boolean isFilterRequestsWithSameHeader() {
        return filterSameHeaderCheckBox.isSelected();
    }

    public boolean isRestrictToScope() {
        return restrictScopeCheckBox.isSelected();
    }

    public String getScopeUrlText() {
        return scopeTextField.getText();
    }
}
