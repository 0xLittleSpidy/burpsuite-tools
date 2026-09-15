// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.collector.ui;

import com.littlespidy.headerinspector.collector.knowledge.HttpDevHeaderDoc;
import com.littlespidy.headerinspector.collector.knowledge.HttpDevKnowledgeBase;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated documentation and reference panel for HTTP headers,
 * embedding the exact explanations, directives, and RFC references
 * scraped from https://http.dev.
 *
 * @author littlespidy
 */
public class HeaderDocPanel extends JPanel {

    private final JLabel headerNameLabel = new JLabel("Select a header");
    private final JLabel categoryBadge = new JLabel("Category");
    private final JLabel typeBadge = new JLabel("Request/Response");
    private final JButton copyLinkBtn = new JButton("Copy Link");
    private final JButton openBrowserBtn = new JButton("Open in Browser");

    private final JLabel summaryLabel = new JLabel("Select a header from the table above to view its exact documentation from http.dev.");
    private final JPanel summaryCard = new JPanel(new BorderLayout(5, 5));

    private final JPanel directivesContainer = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
    private final JLabel directivesTitle = new JLabel("Directives & Syntax:");

    private final JTextArea explanationArea = new JTextArea();

    private final JPanel specsContainer = new JPanel();
    private final JLabel specsTitle = new JLabel("Official Specifications & Standards:");

    private HttpDevHeaderDoc currentDoc = null;
    private String currentHeaderName = "";

    public HeaderDocPanel() {
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

        headerNameLabel.setFont(headerNameLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleAndBadges.add(headerNameLabel);

        styleBadge(categoryBadge, new Color(52, 152, 219), Color.WHITE);
        styleBadge(typeBadge, new Color(149, 165, 166), Color.WHITE);
        categoryBadge.setVisible(false);
        typeBadge.setVisible(false);

        titleAndBadges.add(categoryBadge);
        titleAndBadges.add(typeBadge);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        actions.setOpaque(false);

        copyLinkBtn.setToolTipText("Copy reference URL to clipboard");
        openBrowserBtn.setToolTipText("Open header documentation in default web browser");
        copyLinkBtn.setEnabled(false);
        openBrowserBtn.setEnabled(false);

        copyLinkBtn.addActionListener(e -> {
            String url = (currentDoc != null) ? currentDoc.referenceUrl() : "https://http.dev/headers";
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
            JOptionPane.showMessageDialog(this, "Copied to clipboard:\n" + url, "Reference Copied", JOptionPane.INFORMATION_MESSAGE);
        });

        openBrowserBtn.addActionListener(e -> {
            String url = (currentDoc != null) ? currentDoc.referenceUrl() : "https://http.dev/headers";
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

        // ── 3. Center Content (Explanation + Directives + Specs) ──
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setOpaque(false);

        // Directives Row
        JPanel directivesRow = new JPanel(new BorderLayout(4, 4));
        directivesRow.setOpaque(false);
        directivesTitle.setFont(directivesTitle.getFont().deriveFont(Font.BOLD, 12f));
        directivesRow.add(directivesTitle, BorderLayout.NORTH);
        directivesRow.add(directivesContainer, BorderLayout.CENTER);
        directivesRow.setBorder(new EmptyBorder(6, 0, 8, 0));

        // Explanation Area
        explanationArea.setEditable(false);
        explanationArea.setLineWrap(true);
        explanationArea.setWrapStyleWord(true);
        explanationArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        explanationArea.setMargin(new Insets(8, 8, 8, 8));

        JScrollPane explanationScroll = new JScrollPane(explanationArea);
        explanationScroll.setBorder(BorderFactory.createTitledBorder("Exact Explanation (http.dev)"));
        explanationScroll.setPreferredSize(new Dimension(500, 160));

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
        contentPanel.add(Box.createVerticalStrut(6));
        contentPanel.add(directivesRow);
        contentPanel.add(explanationScroll);
        contentPanel.add(specsRow);

        add(topBanner, BorderLayout.NORTH);
        add(new JScrollPane(contentPanel), BorderLayout.CENTER);
    }

    /**
     * Updates the documentation view for the specified header name and type.
     */
    public void setHeader(String headerName, String typeDisplay) {
        this.currentHeaderName = (headerName != null) ? headerName.trim() : "";
        if (currentHeaderName.isEmpty()) {
            resetView();
            return;
        }

        this.currentDoc = HttpDevKnowledgeBase.get(currentHeaderName);

        headerNameLabel.setText(currentHeaderName);
        if (typeDisplay != null && !typeDisplay.isBlank()) {
            typeBadge.setText(typeDisplay);
            typeBadge.setVisible(true);
        } else {
            typeBadge.setVisible(false);
        }

        if (currentDoc != null) {
            // Known header from http.dev
            categoryBadge.setText(currentDoc.category());
            categoryBadge.setVisible(true);
            copyLinkBtn.setEnabled(true);
            openBrowserBtn.setEnabled(true);

            summaryLabel.setText("<html><b>Summary:</b> " + escapeHtml(currentDoc.summary()) + "</html>");
            explanationArea.setText(currentDoc.explanation());
            explanationArea.setCaretPosition(0);

            // Populate Directives
            directivesContainer.removeAll();
            if (currentDoc.hasDirectives()) {
                directivesTitle.setVisible(true);
                directivesContainer.setVisible(true);
                for (String dir : currentDoc.directives().split(",")) {
                    String d = dir.trim();
                    if (!d.isEmpty()) {
                        JLabel badge = new JLabel(d);
                        styleBadge(badge, new Color(46, 204, 113), Color.WHITE);
                        directivesContainer.add(badge);
                    }
                }
            } else {
                directivesTitle.setVisible(false);
                directivesContainer.setVisible(false);
            }

            // Populate Specifications
            specsContainer.removeAll();
            if (currentDoc.hasSpecifications()) {
                specsTitle.setVisible(true);
                specsContainer.setVisible(true);
                for (HttpDevHeaderDoc.Specification spec : currentDoc.specifications()) {
                    JPanel specRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
                    specRow.setOpaque(false);

                    JLabel titleLbl = new JLabel("• " + spec.title());
                    titleLbl.setFont(titleLbl.getFont().deriveFont(Font.PLAIN, 12f));

                    JButton linkBtn = new JButton("Open Spec ↗");
                    linkBtn.setFont(linkBtn.getFont().deriveFont(10f));
                    linkBtn.setMargin(new Insets(1, 4, 1, 4));
                    linkBtn.addActionListener(e -> {
                        try {
                            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                                Desktop.getDesktop().browse(URI.create(spec.url()));
                            }
                        } catch (Exception ex) {
                            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(spec.url()), null);
                            JOptionPane.showMessageDialog(this, "Copied URL to clipboard:\n" + spec.url(), "Spec URL", JOptionPane.INFORMATION_MESSAGE);
                        }
                    });

                    specRow.add(titleLbl);
                    specRow.add(linkBtn);
                    specsContainer.add(specRow);
                }
            } else {
                specsTitle.setVisible(false);
                specsContainer.setVisible(false);
            }
        } else {
            // Custom or Unrecognized header
            categoryBadge.setText("Custom / Vendor");
            categoryBadge.setVisible(true);
            copyLinkBtn.setEnabled(true);
            openBrowserBtn.setEnabled(true);

            summaryLabel.setText("<html><b>Notice:</b> Header <code>" + escapeHtml(currentHeaderName)
                    + "</code> is not indexed in the standard http.dev catalog (custom application or proprietary vendor header).</html>");
            explanationArea.setText("This header was observed in HTTP traffic but does not have a dedicated entry in http.dev.\n\n"
                    + "Common reasons:\n"
                    + "1. Custom internal application header (e.g. X-User-Id, Authorization-Client, etc.).\n"
                    + "2. Proprietary gateway, reverse proxy, or API management routing token.\n"
                    + "3. Deprecated or non-standard experimental header.\n\n"
                    + "You can search http.dev or standard RFC catalogs using the button below.");
            explanationArea.setCaretPosition(0);

            directivesTitle.setVisible(false);
            directivesContainer.removeAll();
            directivesContainer.setVisible(false);

            specsContainer.removeAll();
            specsTitle.setVisible(true);
            JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            searchRow.setOpaque(false);

            JButton searchBtn = new JButton("Search http.dev for '" + currentHeaderName + "' ↗");
            searchBtn.addActionListener(e -> {
                String searchUrl = "https://http.dev/headers#" + currentHeaderName.toLowerCase();
                try {
                    if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                        Desktop.getDesktop().browse(URI.create(searchUrl));
                    }
                } catch (Exception ex) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(searchUrl), null);
                }
            });
            searchRow.add(searchBtn);
            specsContainer.add(searchRow);
            specsContainer.setVisible(true);
        }

        revalidate();
        repaint();
    }

    private void resetView() {
        headerNameLabel.setText("Select a header");
        categoryBadge.setVisible(false);
        typeBadge.setVisible(false);
        copyLinkBtn.setEnabled(false);
        openBrowserBtn.setEnabled(false);
        summaryLabel.setText("Select a header from the table above to view its exact documentation from http.dev.");
        explanationArea.setText("");
        directivesTitle.setVisible(false);
        directivesContainer.removeAll();
        specsTitle.setVisible(false);
        specsContainer.removeAll();
        revalidate();
        repaint();
    }

    private void styleBadge(JLabel label, Color bgColor, Color fgColor) {
        label.setOpaque(true);
        label.setBackground(bgColor);
        label.setForeground(fgColor);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        label.setBorder(new EmptyBorder(2, 6, 2, 6));
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
