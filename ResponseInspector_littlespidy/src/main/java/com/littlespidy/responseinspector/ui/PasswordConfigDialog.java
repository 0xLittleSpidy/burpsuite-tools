// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import com.littlespidy.responseinspector.engine.PasswordScanner;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Modal dialog enabling users to view, enter, import, and configure target passwords to scan for.
 */
public class PasswordConfigDialog extends JDialog {

    private final PasswordScanner passwordScanner;
    private final JTextArea passwordArea;
    private final JCheckBox caseSensitiveCb;
    private final JLabel countLabel;
    private final Runnable onSaveCallback;

    public PasswordConfigDialog(Frame parent, PasswordScanner passwordScanner, Runnable onSaveCallback) {
        super(parent, "Configure Target Passwords", true);
        this.passwordScanner = passwordScanner;
        this.onSaveCallback = onSaveCallback;

        setLayout(new BorderLayout(8, 8));
        setSize(520, 420);
        setLocationRelativeTo(parent);

        // Header / Instructions
        JPanel headerPanel = new JPanel(new BorderLayout(4, 4));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 12, 4, 12));
        JLabel titleLabel = new JLabel("Target Passwords for Response Analysis");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        JLabel descLabel = new JLabel("<html>Enter or paste target passwords (one per line). Responses will be scanned for these exact passwords.</html>");
        descLabel.setForeground(Color.GRAY);
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descLabel, BorderLayout.SOUTH);
        add(headerPanel, BorderLayout.NORTH);

        // Center: Text area with existing passwords
        passwordArea = new JTextArea();
        passwordArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        List<String> current = passwordScanner.getPasswords();
        if (!current.isEmpty()) {
            passwordArea.setText(String.join("\n", current));
        }

        JScrollPane scrollPane = new JScrollPane(passwordArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Password List (One per line)"));
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBorder(BorderFactory.createEmptyBorder(4, 12, 4, 12));
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        countLabel = new JLabel("Configured: " + current.size() + " passwords");
        centerPanel.add(countLabel, BorderLayout.SOUTH);
        add(centerPanel, BorderLayout.CENTER);

        // Footer / Controls
        JPanel footerPanel = new JPanel(new BorderLayout(8, 8));
        footerPanel.setBorder(BorderFactory.createEmptyBorder(6, 12, 10, 12));

        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        caseSensitiveCb = new JCheckBox("Case-sensitive matching", passwordScanner.isCaseSensitive());
        optionsPanel.add(caseSensitiveCb);

        JButton importBtn = new JButton("Import from File...");
        importBtn.addActionListener(e -> importFromFile());
        optionsPanel.add(importBtn);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            passwordArea.setText("");
            countLabel.setText("Configured: 0 passwords");
        });
        optionsPanel.add(clearBtn);

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> {
            savePasswords();
            dispose();
        });

        actionPanel.add(cancelBtn);
        actionPanel.add(saveBtn);

        footerPanel.add(optionsPanel, BorderLayout.WEST);
        footerPanel.add(actionPanel, BorderLayout.EAST);
        add(footerPanel, BorderLayout.SOUTH);
    }

    private void importFromFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Password Wordlist File");
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                List<String> lines = Files.readAllLines(file.toPath());
                StringBuilder sb = new StringBuilder(passwordArea.getText());
                if (!sb.isEmpty() && !sb.toString().endsWith("\n")) {
                    sb.append("\n");
                }
                for (String line : lines) {
                    if (!line.isBlank()) {
                        sb.append(line.trim()).append("\n");
                    }
                }
                passwordArea.setText(sb.toString());
                int count = (int) Arrays.stream(passwordArea.getText().split("\\R"))
                        .filter(s -> !s.isBlank()).count();
                countLabel.setText("Configured: " + count + " passwords");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error reading file: " + ex.getMessage(),
                        "Import Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void savePasswords() {
        String[] lines = passwordArea.getText().split("\\R");
        List<String> passwords = new ArrayList<>();
        for (String line : lines) {
            if (!line.isBlank()) {
                passwords.add(line.trim());
            }
        }
        passwordScanner.setPasswords(passwords);
        passwordScanner.setCaseSensitive(caseSensitiveCb.isSelected());
        if (onSaveCallback != null) {
            onSaveCallback.run();
        }
    }
}
