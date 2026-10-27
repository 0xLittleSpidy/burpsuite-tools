// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Map;

/**
 * Dedicated readable details dialog for an API endpoint.
 * Opens upon double-clicking an endpoint row in the API Import tab,
 * displaying formatted descriptions, summaries, parameters, and metadata.
 */
public class EndpointDetailsDialog_littlespidy extends JDialog {

    public EndpointDetailsDialog_littlespidy(Window parent, DiscoveredEndpoint_littlespidy endpoint) {
        this(parent, endpoint, null);
    }

    public EndpointDetailsDialog_littlespidy(Window parent, DiscoveredEndpoint_littlespidy endpoint, Runnable onSendToVersionFinder) {
        super(parent, "Endpoint Details: " + (endpoint != null ? (endpoint.getMethod() + " " + endpoint.getPath()) : "Unknown"), ModalityType.APPLICATION_MODAL);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setSize(700, 560);
        setLocationRelativeTo(parent);

        JPanel mainPanel = new JPanel(new BorderLayout(8, 8));
        mainPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        if (endpoint == null) {
            mainPanel.add(new JLabel("No endpoint data available.", JLabel.CENTER), BorderLayout.CENTER);
            setContentPane(mainPanel);
            return;
        }

        // Top info header
        JPanel topInfo = new JPanel(new GridLayout(0, 1, 4, 4));
        topInfo.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JLabel titleLabel = new JLabel(endpoint.getMethod() + " " + endpoint.getPath());
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 15f));
        topInfo.add(titleLabel);

        if (endpoint.getSummary() != null && !endpoint.getSummary().isBlank()) {
            JLabel summaryLabel = new JLabel("Summary: " + endpoint.getSummary());
            summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.PLAIN, 12f));
            topInfo.add(summaryLabel);
        }

        String authText = endpoint.isRequiresAuth() ? "Authentication: Required" : "Authentication: None";
        if (endpoint.getAuthSchemes() != null && !endpoint.getAuthSchemes().isEmpty()) {
            authText += " (" + String.join(", ", endpoint.getAuthSchemes()) + ")";
        }
        JLabel authLabel = new JLabel(authText);
        authLabel.setFont(authLabel.getFont().deriveFont(Font.PLAIN, 11f));
        authLabel.setForeground(endpoint.isRequiresAuth() ? new Color(160, 40, 0) : new Color(0, 120, 40));
        topInfo.add(authLabel);

        if (endpoint.getContentType() != null && !endpoint.getContentType().isBlank()) {
            JLabel ctLabel = new JLabel("Content-Type: " + endpoint.getContentType());
            ctLabel.setFont(ctLabel.getFont().deriveFont(Font.PLAIN, 11f));
            topInfo.add(ctLabel);
        }

        mainPanel.add(topInfo, BorderLayout.NORTH);

        // Center tabs or split for Description & Parameters
        JTabbedPane detailTabs = new JTabbedPane();

        // 1. Description Tab
        JPanel descPanel = new JPanel(new BorderLayout(4, 4));
        descPanel.setBorder(new EmptyBorder(6, 6, 6, 6));

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        String desc = endpoint.getDescription();
        if (desc == null || desc.isBlank()) {
            desc = (endpoint.getSummary() != null && !endpoint.getSummary().isBlank())
                    ? endpoint.getSummary()
                    : "[No detailed description provided for this endpoint]";
        }
        descArea.setText(desc);
        descArea.setCaretPosition(0);

        JScrollPane descScroll = new JScrollPane(descArea);
        descScroll.setBorder(BorderFactory.createTitledBorder("Full Endpoint Description"));
        descPanel.add(descScroll, BorderLayout.CENTER);
        detailTabs.addTab("Description", descPanel);

        // 2. Parameters Tab
        JPanel paramsPanel = new JPanel(new BorderLayout(4, 4));
        paramsPanel.setBorder(new EmptyBorder(6, 6, 6, 6));

        JTextArea paramsArea = new JTextArea();
        paramsArea.setEditable(false);
        paramsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        StringBuilder pSb = new StringBuilder();
        pSb.append("=== Query Parameters ===\n");
        if (endpoint.getQueryParams() != null && !endpoint.getQueryParams().isEmpty()) {
            for (Map.Entry<String, String> q : endpoint.getQueryParams().entrySet()) {
                String type = endpoint.getQueryParamTypes().getOrDefault(q.getKey(), "string");
                pSb.append("  * ").append(q.getKey()).append(" (type: ").append(type).append("): ").append(q.getValue()).append("\n");
            }
        } else {
            pSb.append("  (None)\n");
        }

        pSb.append("\n=== Path Parameters ===\n");
        if (endpoint.getPathParams() != null && !endpoint.getPathParams().isEmpty()) {
            for (Map.Entry<String, String> p : endpoint.getPathParams().entrySet()) {
                String type = endpoint.getPathParamTypes().getOrDefault(p.getKey(), "string");
                pSb.append("  * ").append(p.getKey()).append(" (type: ").append(type).append("): ").append(p.getValue()).append("\n");
            }
        } else {
            pSb.append("  (None)\n");
        }

        pSb.append("\n=== Body Parameters ===\n");
        if (endpoint.getBodyParams() != null && !endpoint.getBodyParams().isEmpty()) {
            for (Map.Entry<String, String> b : endpoint.getBodyParams().entrySet()) {
                String type = endpoint.getBodyParamTypes().getOrDefault(b.getKey(), "string");
                pSb.append("  * ").append(b.getKey()).append(" (type: ").append(type).append("): ").append(b.getValue()).append("\n");
            }
        } else {
            pSb.append("  (None)\n");
        }

        if (endpoint.getRequestBodySample() != null && !endpoint.getRequestBodySample().isBlank()) {
            pSb.append("\n=== Sample Request Body ===\n");
            pSb.append(endpoint.getRequestBodySample()).append("\n");
        }

        paramsArea.setText(pSb.toString());
        paramsArea.setCaretPosition(0);

        JScrollPane paramsScroll = new JScrollPane(paramsArea);
        paramsScroll.setBorder(BorderFactory.createTitledBorder("Parameters & Body Schema"));
        paramsPanel.add(paramsScroll, BorderLayout.CENTER);
        detailTabs.addTab("Parameters", paramsPanel);

        // 3. Headers Tab (if headers present)
        if (endpoint.getHeaders() != null && !endpoint.getHeaders().isEmpty()) {
            JPanel headersPanel = new JPanel(new BorderLayout(4, 4));
            headersPanel.setBorder(new EmptyBorder(6, 6, 6, 6));

            JTextArea headersArea = new JTextArea();
            headersArea.setEditable(false);
            headersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            StringBuilder hSb = new StringBuilder();
            for (Map.Entry<String, String> h : endpoint.getHeaders().entrySet()) {
                hSb.append(h.getKey()).append(": ").append(h.getValue()).append("\n");
            }
            headersArea.setText(hSb.toString());
            headersArea.setCaretPosition(0);

            JScrollPane headersScroll = new JScrollPane(headersArea);
            headersScroll.setBorder(BorderFactory.createTitledBorder("Required / Default Request Headers"));
            headersPanel.add(headersScroll, BorderLayout.CENTER);
            detailTabs.addTab("Headers", headersPanel);
        }

        mainPanel.add(detailTabs, BorderLayout.CENTER);

        // Bottom Action Bar
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));

        if (onSendToVersionFinder != null) {
            JButton sendToVFBtn = new JButton("Send to ResAPI Version Finder");
            sendToVFBtn.addActionListener(e -> {
                dispose();
                onSendToVersionFinder.run();
            });
            bottomBar.add(sendToVFBtn);
        }

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        bottomBar.add(closeBtn);

        mainPanel.add(bottomBar, BorderLayout.SOUTH);

        setContentPane(mainPanel);
    }
}
