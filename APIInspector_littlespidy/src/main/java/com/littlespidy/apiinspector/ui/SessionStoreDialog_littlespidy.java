// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.SessionStore_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Dialog for managing session-specific HTTP headers.
 * Provides a clean text area where users can paste arbitrary HTTP headers (one per line).
 */
public class SessionStoreDialog_littlespidy extends JDialog {

    private final SessionStore_littlespidy sessionStore;
    private final Runnable onSaveCallback;

    private JCheckBox enableCheckBox;
    private JRadioButton authOnlyRadio;
    private JRadioButton allRequestsRadio;
    private JTextArea headersTextArea;

    public SessionStoreDialog_littlespidy(Window parent, SessionStore_littlespidy sessionStore, Runnable onSaveCallback) {
        super(parent, "Session Authentication Store", ModalityType.APPLICATION_MODAL);
        this.sessionStore = sessionStore;
        this.onSaveCallback = onSaveCallback;

        initComponents();
        loadFromStore();
        pack();
        setMinimumSize(new Dimension(560, 420));
        setLocationRelativeTo(parent);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(8, 8));
        contentPane.setBorder(new EmptyBorder(12, 12, 12, 12));

        // 1. General & Scope Section
        JPanel scopeCard = new JPanel();
        scopeCard.setLayout(new BoxLayout(scopeCard, BoxLayout.Y_AXIS));
        scopeCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "General & Scope Settings", TitledBorder.LEFT, TitledBorder.TOP));

        enableCheckBox = new JCheckBox("Enable Session Store Authentication");
        enableCheckBox.setFont(enableCheckBox.getFont().deriveFont(Font.BOLD));
        scopeCard.add(enableCheckBox);
        scopeCard.add(Box.createVerticalStrut(6));

        JPanel scopeRadioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        authOnlyRadio = new JRadioButton("Only endpoints requiring authentication");
        allRequestsRadio = new JRadioButton("All endpoints");
        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(authOnlyRadio);
        scopeGroup.add(allRequestsRadio);
        scopeRadioPanel.add(new JLabel("Apply to:"));
        scopeRadioPanel.add(authOnlyRadio);
        scopeRadioPanel.add(allRequestsRadio);
        scopeCard.add(scopeRadioPanel);

        contentPane.add(scopeCard, BorderLayout.NORTH);

        // 2. HTTP Headers Text Area Section
        JPanel headersCard = new JPanel(new BorderLayout(6, 6));
        headersCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Session HTTP Headers (one per line, e.g. Name: Value)", TitledBorder.LEFT, TitledBorder.TOP));

        headersTextArea = new JTextArea(12, 45);
        headersTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        headersTextArea.setLineWrap(true);
        headersTextArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(headersTextArea);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        headersCard.add(scrollPane, BorderLayout.CENTER);

        JLabel helpLabel = new JLabel("Pasted headers strictly overwrite/replace any existing matching headers on outgoing requests.");
        helpLabel.setFont(helpLabel.getFont().deriveFont(Font.ITALIC, 11f));
        helpLabel.setForeground(Color.GRAY);
        helpLabel.setBorder(new EmptyBorder(4, 4, 2, 4));
        headersCard.add(helpLabel, BorderLayout.SOUTH);

        contentPane.add(headersCard, BorderLayout.CENTER);

        // 3. Bottom Action Buttons
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> onSave());

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        bottomBar.add(cancelBtn);
        bottomBar.add(saveBtn);
        contentPane.add(bottomBar, BorderLayout.SOUTH);

        setContentPane(contentPane);
    }

    private void loadFromStore() {
        if (sessionStore == null) return;
        enableCheckBox.setSelected(sessionStore.isEnabled());
        if (SessionStore_littlespidy.MODE_ALL_REQUESTS.equals(sessionStore.getApplyMode())) {
            allRequestsRadio.setSelected(true);
        } else {
            authOnlyRadio.setSelected(true);
        }
        headersTextArea.setText(sessionStore.getRawHeaders());
    }

    private void onSave() {
        if (sessionStore != null) {
            sessionStore.setEnabled(enableCheckBox.isSelected());
            sessionStore.setApplyMode(allRequestsRadio.isSelected()
                    ? SessionStore_littlespidy.MODE_ALL_REQUESTS
                    : SessionStore_littlespidy.MODE_AUTH_REQUIRED_ONLY);
            sessionStore.setRawHeaders(headersTextArea.getText());
        }

        if (onSaveCallback != null) {
            onSaveCallback.run();
        }

        dispose();
    }
}
