// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import com.littlespidy.quickhelper.model.ExtractionOptions_littlespidy;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;
import com.littlespidy.quickhelper.service.DomainExtractorService_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Tab component for extracting unique domain names and URLs from Burp Suite's site map.
 */
public class DomainExtractorTab_littlespidy extends JPanel {

    private final DomainExtractorService_littlespidy extractorService;
    private final ClipboardService_littlespidy clipboardService;

    private final JCheckBox schemaCheckBox;
    private final JCheckBox inScopeCheckBox;
    private final JButton extractBtn;
    private final JButton clearBtn;
    private final JLabel countLabel;
    private final JTextArea outputArea;

    public DomainExtractorTab_littlespidy(DomainExtractorService_littlespidy extractorService,
                                         ClipboardService_littlespidy clipboardService) {
        this.extractorService = extractorService;
        this.clipboardService = clipboardService;

        setLayout(new BorderLayout(0, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        this.schemaCheckBox = new JCheckBox("Include HTTP Schema (https:// or http://)");
        this.inScopeCheckBox = new JCheckBox("In-Scope Only");
        this.extractBtn = new JButton("Extract Domains and Copy to Clipboard");
        this.clearBtn = new JButton("Clear");
        this.countLabel = new JLabel("Extracted: 0 domains");
        this.outputArea = new JTextArea();

        initUi();
    }

    private void initUi() {
        // Info Banner
        JPanel bannerPanel = new JPanel(new BorderLayout());
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(8, 12, 8, 12)
        ));

        JLabel titleLabel = new JLabel("Quick Helper: Site Map Domain Extractor");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));

        JLabel descLabel = new JLabel("Queries the Burp Suite Target Site Map, deduplicates unique domain names or URLs, "
                + "and copies them directly to your system clipboard with natural alphabetical sorting.");
        descLabel.setFont(descLabel.getFont().deriveFont(Font.PLAIN, 11f));

        JPanel bannerTextPanel = new JPanel();
        bannerTextPanel.setLayout(new BoxLayout(bannerTextPanel, BoxLayout.Y_AXIS));
        bannerTextPanel.add(titleLabel);
        bannerTextPanel.add(Box.createVerticalStrut(3));
        bannerTextPanel.add(descLabel);

        bannerPanel.add(bannerTextPanel, BorderLayout.CENTER);
        add(bannerPanel, BorderLayout.NORTH);

        // Center: Controls and Output Area
        JPanel centerPanel = new JPanel(new BorderLayout(0, 8));

        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        controlsPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(6, 8, 6, 8)
        ));

        schemaCheckBox.setFont(schemaCheckBox.getFont().deriveFont(Font.PLAIN, 11f));
        controlsPanel.add(schemaCheckBox);

        inScopeCheckBox.setFont(inScopeCheckBox.getFont().deriveFont(Font.PLAIN, 11f));
        controlsPanel.add(inScopeCheckBox);

        controlsPanel.add(new JSeparator(SwingConstants.VERTICAL));

        extractBtn.setFont(extractBtn.getFont().deriveFont(Font.BOLD, 11f));
        extractBtn.addActionListener(e -> executeExtraction());
        controlsPanel.add(extractBtn);

        clearBtn.setFont(clearBtn.getFont().deriveFont(Font.PLAIN, 11f));
        clearBtn.addActionListener(e -> {
            outputArea.setText("");
            countLabel.setText("Extracted: 0 domains");
        });
        controlsPanel.add(clearBtn);

        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD, 11f));
        controlsPanel.add(countLabel);

        centerPanel.add(controlsPanel, BorderLayout.NORTH);

        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setBackground(new Color(25, 25, 25));
        outputArea.setForeground(new Color(220, 220, 220));
        outputArea.setBorder(new EmptyBorder(6, 8, 6, 8));

        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Extracted Domain Results (One per line)"));
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);
    }

    private void executeExtraction() {
        extractBtn.setEnabled(false);
        boolean schema = schemaCheckBox.isSelected();
        boolean inScope = inScopeCheckBox.isSelected();

        ExtractionOptions_littlespidy options = new ExtractionOptions_littlespidy(schema, inScope);

        CompletableFuture.supplyAsync(() -> extractorService.extractDomains(options))
                .thenAccept(domains -> SwingUtilities.invokeLater(() -> {
                    StringBuilder sb = new StringBuilder();
                    for (String d : domains) {
                        sb.append(d).append("\n");
                    }
                    outputArea.setText(sb.toString());
                    outputArea.setCaretPosition(0);

                    if (!domains.isEmpty() && clipboardService != null) {
                        clipboardService.copyToClipboard(sb.toString().trim());
                    }

                    countLabel.setText("Extracted: " + domains.size() + " unique domains (Copied to clipboard)");
                    extractBtn.setEnabled(true);
                }))
                .exceptionally(ex -> {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(this,
                                "Error extracting domains: " + ex.getMessage(),
                                "Extraction Error",
                                JOptionPane.ERROR_MESSAGE);
                        extractBtn.setEnabled(true);
                    });
                    return null;
                });
    }
}
