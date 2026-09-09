// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.littlespidy.jwtcomparator.model.JWTParser;
import com.littlespidy.jwtcomparator.model.JWTTokenModel;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;

/**
 * Visual card representing a single token slot with domain label, paste input, and quick metadata.
 */
public class TokenCardPanel extends JPanel {

    public interface TokenCardListener {
        void onTokenChanged(TokenCardPanel card);
        void onRemoveRequested(TokenCardPanel card);
    }

    private final JWTTokenModel model;
    private final TokenCardListener listener;

    private final JTextField labelField;
    private final JTextArea rawTextArea;
    private final JLabel statusBadge;
    private final JLabel infoLabel;
    private final JButton removeButton;

    private boolean updatingProgrammatically = false;

    public TokenCardPanel(JWTTokenModel model, TokenCardListener listener) {
        this.model = model;
        this.listener = listener;

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Separator.foreground") != null ?
                        UIManager.getColor("Separator.foreground") : Color.GRAY, 1, true),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)
        ));

        // ── Header Bar ──
        JPanel headerPanel = new JPanel(new BorderLayout(8, 5));

        JPanel labelContainer = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JLabel tokenTitle = new JLabel("Token " + model.getSlotIndex() + ":");
        tokenTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));

        labelField = new JTextField(model.getLabel(), 18);
        labelField.setToolTipText("Domain or description (e.g. api.domain-a.com, Admin Token)");
        labelField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateLabel(); }
            @Override public void removeUpdate(DocumentEvent e) { updateLabel(); }
            @Override public void changedUpdate(DocumentEvent e) { updateLabel(); }
            private void updateLabel() {
                if (!updatingProgrammatically) {
                    model.setLabel(labelField.getText());
                    if (listener != null) listener.onTokenChanged(TokenCardPanel.this);
                }
            }
        });

        labelContainer.add(tokenTitle);
        labelContainer.add(labelField);

        statusBadge = new JLabel("Empty");
        statusBadge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        statusBadge.setForeground(Color.GRAY);
        labelContainer.add(statusBadge);

        headerPanel.add(labelContainer, BorderLayout.WEST);

        // Actions on header right
        JPanel headerActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));

        JButton pasteBtn = new JButton("📋 Paste");
        pasteBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        pasteBtn.addActionListener(e -> handlePaste());

        JButton viewJsonBtn = new JButton("🔍 View Decoded");
        viewJsonBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        viewJsonBtn.addActionListener(e -> showDecodedDialog());

        JButton clearBtn = new JButton("🧹 Clear");
        clearBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        clearBtn.addActionListener(e -> clearToken());

        removeButton = new JButton("✕");
        removeButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        removeButton.setForeground(new Color(180, 40, 40));
        removeButton.setToolTipText("Remove this token slot");
        removeButton.addActionListener(e -> {
            if (listener != null) listener.onRemoveRequested(TokenCardPanel.this);
        });

        headerActions.add(pasteBtn);
        headerActions.add(viewJsonBtn);
        headerActions.add(clearBtn);
        headerActions.add(removeButton);

        headerPanel.add(headerActions, BorderLayout.EAST);
        add(headerPanel, BorderLayout.NORTH);

        // ── Raw JWT Input Area ──
        rawTextArea = new JTextArea(3, 30);
        rawTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        rawTextArea.setLineWrap(true);
        rawTextArea.setWrapStyleWord(false);
        rawTextArea.setToolTipText("Paste raw JWT token here (eyJ...)");

        rawTextArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { handleInputChanged(); }
            @Override public void removeUpdate(DocumentEvent e) { handleInputChanged(); }
            @Override public void changedUpdate(DocumentEvent e) { handleInputChanged(); }
        });

        JScrollPane scroll = new JScrollPane(rawTextArea);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        add(scroll, BorderLayout.CENTER);

        // ── Metadata Footer ──
        infoLabel = new JLabel("Ready - paste or send a token");
        infoLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        infoLabel.setForeground(Color.GRAY);
        add(infoLabel, BorderLayout.SOUTH);

        refreshView();
    }

    private void handleInputChanged() {
        if (updatingProgrammatically) return;

        String raw = rawTextArea.getText().trim();
        JWTParser.parseToken(raw, model);
        refreshView();

        if (listener != null) {
            listener.onTokenChanged(this);
        }
    }

    private void handlePaste() {
        try {
            String clipboardData = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(DataFlavor.stringFlavor);
            if (clipboardData != null && !clipboardData.trim().isEmpty()) {
                setRawToken(clipboardData.trim());
            }
        } catch (Exception ex) {
            // ignore
        }
    }

    public void setRawToken(String token) {
        updatingProgrammatically = true;
        rawTextArea.setText(token);
        updatingProgrammatically = false;
        JWTParser.parseToken(token, model);
        refreshView();
        if (listener != null) {
            listener.onTokenChanged(this);
        }
    }

    public void setTokenWithLabel(String token, String label) {
        updatingProgrammatically = true;
        if (label != null && !label.trim().isEmpty()) {
            model.setLabel(label.trim());
            labelField.setText(label.trim());
        }
        rawTextArea.setText(token);
        updatingProgrammatically = false;
        JWTParser.parseToken(token, model);
        refreshView();
        if (listener != null) {
            listener.onTokenChanged(this);
        }
    }

    public void clearToken() {
        updatingProgrammatically = true;
        rawTextArea.setText("");
        updatingProgrammatically = false;
        model.clear();
        refreshView();
        if (listener != null) {
            listener.onTokenChanged(this);
        }
    }

    public void setRemoveEnabled(boolean enabled) {
        removeButton.setEnabled(enabled);
        removeButton.setVisible(enabled);
    }

    public void refreshView() {
        if (!model.isValid()) {
            if (model.getRawToken().isEmpty()) {
                statusBadge.setText("Empty");
                statusBadge.setForeground(Color.GRAY);
                infoLabel.setText("Ready - paste raw token or send from Burp");
                infoLabel.setForeground(Color.GRAY);
            } else {
                statusBadge.setText("Invalid JWT");
                statusBadge.setForeground(new Color(200, 40, 40));
                infoLabel.setText("Error: " + model.getParseError());
                infoLabel.setForeground(new Color(200, 40, 40));
            }
        } else {
            statusBadge.setText("Valid (" + model.getAlgorithm() + ")");
            statusBadge.setForeground(new Color(30, 140, 40));

            StringBuilder sb = new StringBuilder();
            sb.append("Alg: ").append(model.getAlgorithm());
            if (!"-".equals(model.getSubject())) {
                sb.append(" | Sub: ").append(model.getSubject());
            }
            if (!"-".equals(model.getIssuer())) {
                sb.append(" | Iss: ").append(model.getIssuer());
            }

            String expHuman = model.getTimestampHumanReadable("exp");
            if (expHuman != null) {
                sb.append(" | Exp: ").append(expHuman);
            }

            infoLabel.setText(sb.toString());
            infoLabel.setForeground(UIManager.getColor("Label.foreground"));
        }
    }

    private void showDecodedDialog() {
        if (!model.isValid()) {
            JOptionPane.showMessageDialog(this,
                    "No valid JWT token to display. Please paste or send a valid JWT first.",
                    "Cannot View Decoded", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this),
                "Decoded: Token " + model.getSlotIndex() + " (" + model.getLabel() + ")",
                Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(8, 8));
        dialog.setSize(650, 500);
        dialog.setLocationRelativeTo(this);

        JTabbedPane tabs = new JTabbedPane();

        JTextArea payloadArea = new JTextArea(model.getPrettyPayloadJson());
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadArea.setEditable(false);
        tabs.addTab("Payload Claims (" + model.getPayloadClaims().size() + ")", new JScrollPane(payloadArea));

        JTextArea headerArea = new JTextArea(model.getPrettyHeaderJson());
        headerArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        headerArea.setEditable(false);
        tabs.addTab("Header Claims (" + model.getHeaderClaims().size() + ")", new JScrollPane(headerArea));

        dialog.add(tabs, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        btnPanel.add(closeBtn);
        dialog.add(btnPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    public JWTTokenModel getModel() {
        return model;
    }
}
