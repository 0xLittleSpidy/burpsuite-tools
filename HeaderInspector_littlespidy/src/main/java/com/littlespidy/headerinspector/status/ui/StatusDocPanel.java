// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.status.ui;

import com.littlespidy.headerinspector.status.knowledge.HttpDevStatusDoc;
import com.littlespidy.headerinspector.status.knowledge.HttpDevStatusKnowledgeBase;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated documentation and reference panel for HTTP status codes,
 * embedding the exact explanations, class classifications, SEO/caching impact,
 * client actions, and RFC specifications scraped from https://http.dev.
 *
 * @author littlespidy
 */
public class StatusDocPanel extends JPanel {

    private final JLabel statusNameLabel = new JLabel("Select an HTTP status code");
    private final JLabel classBadge = new JLabel("Class");
    private final JLabel actionBadge = new JLabel("Client Action");
    private final JButton copyLinkBtn = new JButton("Copy Link");
    private final JButton openBrowserBtn = new JButton("Open in Browser");

    private final JLabel summaryLabel = new JLabel("Select an HTTP status code from the table above to view its exact documentation from http.dev.");
    private final JPanel summaryCard = new JPanel(new BorderLayout(5, 5));

    private final JTextArea explanationArea = new JTextArea();

    private final JPanel specsContainer = new JPanel();
    private final JLabel specsTitle = new JLabel("Official Specifications & Standards:");

    private HttpDevStatusDoc currentDoc = null;
    private int currentStatusCode = 0;

    public StatusDocPanel() {
        super(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(10, 12, 10, 12));
        initComponents();
    }

    private void initComponents() {
        // ── 1. Top Header Banner ──
        JPanel topBanner = new JPanel(new BorderLayout(8, 8));
        topBanner.setOpaque(false);

        JPanel titleAndBadges = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        titleAndBadges.setOpaque(false);

        statusNameLabel.setFont(statusNameLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleAndBadges.add(statusNameLabel);

        styleBadge(classBadge, new Color(52, 152, 219), Color.WHITE);
        styleBadge(actionBadge, new Color(149, 165, 166), Color.WHITE);
        classBadge.setVisible(false);
        actionBadge.setVisible(false);

        titleAndBadges.add(classBadge);
        titleAndBadges.add(actionBadge);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        actions.setOpaque(false);

        copyLinkBtn.setToolTipText("Copy reference URL to clipboard");
        openBrowserBtn.setToolTipText("Open status documentation in default web browser");
        copyLinkBtn.setEnabled(false);
        openBrowserBtn.setEnabled(false);

        copyLinkBtn.addActionListener(e -> {
            String url = (currentDoc != null) ? currentDoc.referenceUrl() : "https://http.dev/status";
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
            JOptionPane.showMessageDialog(this, "Copied to clipboard:\n" + url, "Reference Copied", JOptionPane.INFORMATION_MESSAGE);
        });

        openBrowserBtn.addActionListener(e -> {
            String url = (currentDoc != null) ? currentDoc.referenceUrl() : "https://http.dev/status";
            try {
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    Desktop.getDesktop().browse(URI.create(url));
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Could not open browser: " + ex.getMessage(), "Browser Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        actions.add(copyLinkBtn);
        actions.add(openBrowserBtn);

        topBanner.add(titleAndBadges, BorderLayout.WEST);
        topBanner.add(actions, BorderLayout.EAST);

        // ── 2. Summary Card ──
        summaryCard.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(210, 215, 220), 1, true),
                new EmptyBorder(8, 10, 8, 10)
        ));
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.ITALIC, 13f));
        summaryCard.add(summaryLabel, BorderLayout.CENTER);

        // ── 3. Center Content (Explanation + Specs) ──
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setOpaque(false);

        // Explanation Area
        explanationArea.setEditable(false);
        explanationArea.setLineWrap(true);
        explanationArea.setWrapStyleWord(true);
        explanationArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        explanationArea.setMargin(new Insets(8, 8, 8, 8));

        JScrollPane explanationScroll = new JScrollPane(explanationArea);
        explanationScroll.setBorder(BorderFactory.createTitledBorder("Status Semantics, SEO Impact & Actions (http.dev)"));
        explanationScroll.setPreferredSize(new Dimension(500, 180));

        // Specifications Container
        specsContainer.setLayout(new BoxLayout(specsContainer, BoxLayout.Y_AXIS));
        specsContainer.setOpaque(false);
        specsTitle.setFont(specsTitle.getFont().deriveFont(Font.BOLD, 12f));
        JPanel specsRow = new JPanel(new BorderLayout(4, 4));
        specsRow.setOpaque(false);
        specsRow.setBorder(new EmptyBorder(8, 0, 4, 0));
        specsRow.add(specsTitle, BorderLayout.NORTH);
        specsRow.add(specsContainer, BorderLayout.CENTER);

        contentPanel.add(summaryCard);
        contentPanel.add(Box.createVerticalStrut(8));
        contentPanel.add(explanationScroll);
        contentPanel.add(specsRow);

        add(topBanner, BorderLayout.NORTH);
        add(new JScrollPane(contentPanel), BorderLayout.CENTER);
    }

    public void setStatus(int statusCode) {
        this.currentStatusCode = statusCode;
        if (statusCode <= 0) {
            resetView();
            return;
        }

        this.currentDoc = HttpDevStatusKnowledgeBase.get(statusCode);
        String reason = HttpDevStatusKnowledgeBase.getReasonPhrase(statusCode);
        statusNameLabel.setText(statusCode + " " + reason);

        if (currentDoc != null) {
            classBadge.setText(currentDoc.statusClass());
            styleBadgeByClass(classBadge, statusCode);
            classBadge.setVisible(true);

            if (currentDoc.clientAction() != null && !currentDoc.clientAction().isBlank()) {
                actionBadge.setText("Action: " + currentDoc.clientAction());
                styleBadge(actionBadge, new Color(52, 73, 94), Color.WHITE);
                actionBadge.setVisible(true);
            } else {
                actionBadge.setVisible(false);
            }

            copyLinkBtn.setEnabled(true);
            openBrowserBtn.setEnabled(true);

            summaryLabel.setText("<html><b>Summary:</b> " + escapeHtml(currentDoc.summary())
                    + "<br><b>Meaning:</b> " + escapeHtml(currentDoc.meaning()) + "</html>");
            explanationArea.setText(currentDoc.explanation());
            explanationArea.setCaretPosition(0);

            specsContainer.removeAll();
            if (currentDoc.hasSpecifications()) {
                specsTitle.setVisible(true);
                for (HttpDevStatusDoc.Specification spec : currentDoc.specifications()) {
                    JPanel specItem = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
                    specItem.setOpaque(false);

                    JLabel specLabel = new JLabel("• " + spec.title());
                    specLabel.setFont(specLabel.getFont().deriveFont(Font.PLAIN, 12f));

                    JButton openSpecBtn = new JButton("View RFC ↗");
                    openSpecBtn.setFont(openSpecBtn.getFont().deriveFont(10f));
                    openSpecBtn.setMargin(new Insets(1, 4, 1, 4));
                    openSpecBtn.addActionListener(e -> {
                        try {
                            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                                Desktop.getDesktop().browse(URI.create(spec.url()));
                            }
                        } catch (Exception ex) {
                            JOptionPane.showMessageDialog(this, "Could not open RFC link: " + ex.getMessage());
                        }
                    });

                    specItem.add(specLabel);
                    specItem.add(openSpecBtn);
                    specsContainer.add(specItem);
                }
            } else {
                specsTitle.setVisible(false);
            }
        } else {
            String fallbackClass = HttpDevStatusKnowledgeBase.getStatusClass(statusCode);
            classBadge.setText(fallbackClass);
            styleBadgeByClass(classBadge, statusCode);
            classBadge.setVisible(true);

            actionBadge.setVisible(false);
            copyLinkBtn.setEnabled(false);
            openBrowserBtn.setEnabled(false);

            summaryLabel.setText("<html><i>Status " + statusCode + " is not present in http.dev reference (Custom or unmapped status code).</i></html>");
            explanationArea.setText("No official http.dev documentation available for status code " + statusCode + ".\n" +
                    "This code may be generated by custom backend logic or a non-standard gateway.");
            explanationArea.setCaretPosition(0);
            specsContainer.removeAll();
            specsTitle.setVisible(false);
        }

        revalidate();
        repaint();
    }

    public void resetView() {
        this.currentDoc = null;
        this.currentStatusCode = 0;
        statusNameLabel.setText("Select an HTTP status code");
        classBadge.setVisible(false);
        actionBadge.setVisible(false);
        copyLinkBtn.setEnabled(false);
        openBrowserBtn.setEnabled(false);
        summaryLabel.setText("Select an HTTP status code from the table above to view its exact documentation from http.dev.");
        explanationArea.setText("");
        specsContainer.removeAll();
        specsTitle.setVisible(false);
        revalidate();
        repaint();
    }

    private void styleBadgeByClass(JLabel label, int code) {
        if (code >= 100 && code < 200) {
            styleBadge(label, new Color(52, 152, 219), Color.WHITE); // 1xx Blue
        } else if (code >= 200 && code < 300) {
            styleBadge(label, new Color(46, 204, 113), Color.WHITE); // 2xx Green
        } else if (code >= 300 && code < 400) {
            styleBadge(label, new Color(243, 156, 18), Color.WHITE); // 3xx Orange
        } else if (code >= 400 && code < 500) {
            styleBadge(label, new Color(230, 126, 34), Color.WHITE); // 4xx Dark Orange / Red
        } else if (code >= 500 && code < 600) {
            styleBadge(label, new Color(231, 76, 60), Color.WHITE);  // 5xx Red
        } else {
            styleBadge(label, new Color(155, 89, 182), Color.WHITE); // Vendor / Extended Purple
        }
    }

    private void styleBadge(JLabel label, Color bg, Color fg) {
        label.setOpaque(true);
        label.setBackground(bg);
        label.setForeground(fg);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        label.setBorder(new EmptyBorder(3, 8, 3, 8));
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
