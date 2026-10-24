// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.function.Consumer;

/**
 * Modal dialog allowing users to manually enter an API endpoint into Hidden API Storage.
 */
public class AddHiddenEndpointDialog_littlespidy extends JDialog {

    private final JTextField urlField;
    private final JComboBox<String> methodCombo;
    private final JComboBox<String> sourceCombo;
    private final JTextField statusField;
    private final JTextField paramsField;
    private final JTextArea notesArea;

    public AddHiddenEndpointDialog_littlespidy(Window owner, Consumer<HiddenEndpoint_littlespidy> onSaveCallback) {
        super(owner, "Add Endpoint to Hidden API Storage", ModalityType.APPLICATION_MODAL);
        setLayout(new BorderLayout(8, 8));
        setSize(520, 380);
        setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(12, 14, 12, 14));

        // URL Field
        mainPanel.add(new JLabel("Endpoint URL / Path:"));
        mainPanel.add(Box.createVerticalStrut(4));
        urlField = new JTextField("https://api.example.com/api/v2/internal/config");
        mainPanel.add(urlField);
        mainPanel.add(Box.createVerticalStrut(10));

        // Method, Source, Status Row
        JPanel rowPanel = new JPanel(new GridLayout(1, 3, 10, 0));

        JPanel methodBox = new JPanel(new BorderLayout(2, 2));
        methodBox.add(new JLabel("Method:"), BorderLayout.NORTH);
        methodCombo = new JComboBox<>(new String[]{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"});
        methodBox.add(methodCombo, BorderLayout.CENTER);
        rowPanel.add(methodBox);

        JPanel sourceBox = new JPanel(new BorderLayout(2, 2));
        sourceBox.add(new JLabel("Source:"), BorderLayout.NORTH);
        sourceCombo = new JComboBox<>(new String[]{
                "Manual Entry",
                "Endpoint Discovery",
                "JS Analysis",
                "Version Finder",
                "Proxy History",
                "Repeater",
                "Target Site Map",
                "Logger",
                "Other Tool"
        });
        sourceBox.add(sourceCombo, BorderLayout.CENTER);
        rowPanel.add(sourceBox);

        JPanel statusBox = new JPanel(new BorderLayout(2, 2));
        statusBox.add(new JLabel("Status Code:"), BorderLayout.NORTH);
        statusField = new JTextField("200");
        statusBox.add(statusField, BorderLayout.CENTER);
        rowPanel.add(statusBox);

        mainPanel.add(rowPanel);
        mainPanel.add(Box.createVerticalStrut(10));

        // Parameters Field
        mainPanel.add(new JLabel("Parameters Summary:"));
        mainPanel.add(Box.createVerticalStrut(4));
        paramsField = new JTextField("format=json, includeHidden=true");
        mainPanel.add(paramsField);
        mainPanel.add(Box.createVerticalStrut(10));

        // Notes Area
        mainPanel.add(new JLabel("Notes / Tags:"));
        mainPanel.add(Box.createVerticalStrut(4));
        notesArea = new JTextArea(3, 30);
        notesArea.setLineWrap(true);
        notesArea.setWrapStyleWord(true);
        notesArea.setText("Manually logged endpoint from reconnaissance.");
        JScrollPane notesScroll = new JScrollPane(notesArea);
        mainPanel.add(notesScroll);

        add(mainPanel, BorderLayout.CENTER);

        // Buttons Panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(cancelBtn);

        JButton saveBtn = new JButton("Save Endpoint");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please specify an endpoint URL or path.", "Input Required", JOptionPane.WARNING_MESSAGE);
                return;
            }

            int statusCode = 0;
            String statusRaw = statusField.getText().trim();
            if (!statusRaw.isEmpty()) {
                try {
                    statusCode = Integer.parseInt(statusRaw);
                } catch (NumberFormatException ignored) {
                }
            }

            String method = (String) methodCombo.getSelectedItem();
            String source = (String) sourceCombo.getSelectedItem();
            String params = paramsField.getText().trim();
            String notes = notesArea.getText().trim();

            HiddenEndpoint_littlespidy endpoint = new HiddenEndpoint_littlespidy(
                    source,
                    method,
                    url,
                    url,
                    statusCode,
                    notes,
                    null,
                    null
            );
            endpoint.setParametersSummary(params);

            if (onSaveCallback != null) {
                onSaveCallback.accept(endpoint);
            }
            dispose();
        });
        buttonPanel.add(saveBtn);

        add(buttonPanel, BorderLayout.SOUTH);
    }
}
