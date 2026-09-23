// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.ui;

import com.littlespidy.sessionexpiration.cookiestore.knowledge.CookieDocRecord;
import com.littlespidy.sessionexpiration.cookiestore.knowledge.CookieSearchFetcher;
import com.littlespidy.sessionexpiration.cookiestore.knowledge.CookieSearchKnowledgeBase;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;

/**
 * Dedicated reference and documentation panel for web cookies,
 * embedding category classifications, behavioral explanations, scripts,
 * and related cookies scraped from https://www.cookiesearch.org/.
 *
 * Modeled after HeaderDocPanel with offline database support and automatic
 * live background fetching.
 *
 * @author littlespidy
 */
public class CookieDocPanel extends JPanel {

    private final JLabel cookieNameLabel = new JLabel("Select a cookie");
    private final JLabel categoryBadge = new JLabel("Category");
    private final JLabel sourceBadge = new JLabel("Request/Response");
    private final JLabel scriptBadge = new JLabel("Script/Provider");

    private final JButton fetchLiveBtn = new JButton("🔄 Re-check cookiesearch.org");
    private final JButton copyLinkBtn = new JButton("Copy Link");
    private final JButton openBrowserBtn = new JButton("Open in Browser");

    private final JLabel statusIndicator = new JLabel("");

    private final JTextArea explanationArea = new JTextArea();

    private final JPanel relatedContainer = new JPanel();
    private final JLabel relatedTitle = new JLabel("Related Cookies:");

    private CookieDocRecord currentDoc = null;
    private String currentCookieName = "";
    private String currentSource = "";

    public CookieDocPanel() {
        super(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(10, 12, 10, 12));
        initComponents();
    }

    private void initComponents() {
        // ── 1. Top Header Banner ─────────────────────────────────────────────
        JPanel topContainer = new JPanel(new BorderLayout(4, 4));
        topContainer.setOpaque(false);

        JPanel topBanner = new JPanel(new BorderLayout(8, 8));
        topBanner.setOpaque(false);

        JPanel titleAndBadges = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        titleAndBadges.setOpaque(false);

        cookieNameLabel.setFont(cookieNameLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleAndBadges.add(cookieNameLabel);

        styleBadge(categoryBadge, new Color(39, 174, 96), Color.WHITE);
        styleBadge(sourceBadge, new Color(149, 165, 166), Color.WHITE);
        styleBadge(scriptBadge, new Color(52, 73, 94), Color.WHITE);

        categoryBadge.setVisible(false);
        sourceBadge.setVisible(false);
        scriptBadge.setVisible(false);

        titleAndBadges.add(categoryBadge);
        titleAndBadges.add(sourceBadge);
        titleAndBadges.add(scriptBadge);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        actions.setOpaque(false);

        fetchLiveBtn.setFont(fetchLiveBtn.getFont().deriveFont(11f));
        fetchLiveBtn.setToolTipText("Force-query https://www.cookiesearch.org/ for live documentation (bypasses cache; does not contact target host)");
        fetchLiveBtn.setEnabled(false);
        fetchLiveBtn.addActionListener(e -> {
            if (!currentCookieName.isEmpty()) {
                performLiveFetch(currentCookieName, true);
            }
        });

        copyLinkBtn.setFont(copyLinkBtn.getFont().deriveFont(11f));
        copyLinkBtn.setToolTipText("Copy reference URL to clipboard");
        copyLinkBtn.setEnabled(false);
        copyLinkBtn.addActionListener(e -> {
            String url = (currentDoc != null && currentDoc.referenceUrl() != null && !currentDoc.referenceUrl().isBlank())
                    ? currentDoc.referenceUrl()
                    : "https://www.cookiesearch.org/cookies/?cookie-id=" + currentCookieName;
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
            JOptionPane.showMessageDialog(this, "Copied to clipboard:\n" + url, "Reference Copied", JOptionPane.INFORMATION_MESSAGE);
        });

        openBrowserBtn.setFont(openBrowserBtn.getFont().deriveFont(11f));
        openBrowserBtn.setToolTipText("Open cookie documentation in default web browser");
        openBrowserBtn.setEnabled(false);
        openBrowserBtn.addActionListener(e -> {
            String url = (currentDoc != null && currentDoc.referenceUrl() != null && !currentDoc.referenceUrl().isBlank())
                    ? currentDoc.referenceUrl()
                    : "https://www.cookiesearch.org/cookies/?cookie-id=" + currentCookieName;
            try {
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    Desktop.getDesktop().browse(URI.create(url));
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Could not open browser: " + ex.getMessage(), "Browser Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        actions.add(fetchLiveBtn);
        actions.add(copyLinkBtn);
        actions.add(openBrowserBtn);

        topBanner.add(titleAndBadges, BorderLayout.WEST);
        topBanner.add(actions, BorderLayout.EAST);

        // Status indicator row
        statusIndicator.setFont(statusIndicator.getFont().deriveFont(Font.ITALIC, 11f));
        statusIndicator.setForeground(new Color(100, 110, 120));
        statusIndicator.setBorder(new EmptyBorder(0, 12, 2, 0));

        topContainer.add(topBanner, BorderLayout.NORTH);
        topContainer.add(statusIndicator, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        // ── 2. Content Center Area ───────────────────────────────────────────
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setOpaque(false);

        // Explanation & Behavioral Details Area
        JPanel explanationSection = new JPanel(new BorderLayout(4, 4));
        explanationSection.setOpaque(false);
        JLabel explanationTitle = new JLabel("Description & Purpose (from cookiesearch.org):");
        explanationTitle.setFont(explanationTitle.getFont().deriveFont(Font.BOLD, 12f));
        explanationSection.add(explanationTitle, BorderLayout.NORTH);

        explanationArea.setEditable(false);
        explanationArea.setLineWrap(true);
        explanationArea.setWrapStyleWord(true);
        explanationArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        explanationArea.setBackground(new Color(252, 253, 255));
        explanationArea.setText("Select a cookie from the table above to view its classification, purpose, and behavioral description from cookiesearch.org.");
        explanationArea.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(210, 215, 220), 1, true),
                new EmptyBorder(10, 12, 10, 12)
        ));
        explanationSection.add(explanationArea, BorderLayout.CENTER);
        contentPanel.add(explanationSection);
        contentPanel.add(Box.createVerticalStrut(10));

        // Related Cookies Section
        JPanel relatedSection = new JPanel(new BorderLayout(4, 4));
        relatedSection.setOpaque(false);
        relatedTitle.setFont(relatedTitle.getFont().deriveFont(Font.BOLD, 12f));
        relatedTitle.setVisible(false);
        relatedSection.add(relatedTitle, BorderLayout.NORTH);

        relatedContainer.setLayout(new FlowLayout(FlowLayout.LEFT, 6, 4));
        relatedContainer.setOpaque(false);
        relatedContainer.setVisible(false);
        relatedSection.add(relatedContainer, BorderLayout.CENTER);
        contentPanel.add(relatedSection);

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(12);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Updates the panel for the specified cookie name and direction source.
     */
    public void setCookie(String cookieName, String source) {
        if (cookieName == null || cookieName.isBlank()) {
            resetView();
            return;
        }

        this.currentCookieName = cookieName.trim();
        this.currentSource = (source != null) ? source : "";

        cookieNameLabel.setText(currentCookieName);
        fetchLiveBtn.setEnabled(true);
        copyLinkBtn.setEnabled(true);
        openBrowserBtn.setEnabled(true);

        if (!currentSource.isBlank()) {
            sourceBadge.setText(currentSource);
            sourceBadge.setVisible(true);
        } else {
            sourceBadge.setVisible(false);
        }

        // 1. Check offline knowledge base
        CookieDocRecord doc = CookieSearchKnowledgeBase.get(currentCookieName);
        if (doc != null) {
            this.currentDoc = doc;
            statusIndicator.setText("Loaded from offline knowledge base (cookiesearch.org).");
            renderDoc(doc);
        } else {
            // Not in offline DB: show notice and auto-fetch from site in background
            this.currentDoc = null;
            categoryBadge.setText("Searching...");
            categoryBadge.setBackground(new Color(149, 165, 166));
            categoryBadge.setVisible(true);
            scriptBadge.setVisible(false);

            statusIndicator.setText("🌐 Fetching live definition from cookiesearch.org for '" + currentCookieName + "'...");
            explanationArea.setText("Querying https://www.cookiesearch.org/ for cookie specifications and meaning...");

            relatedTitle.setVisible(false);
            relatedContainer.removeAll();
            relatedContainer.setVisible(false);

            performLiveFetch(currentCookieName, false);
        }
    }

    private void performLiveFetch(String cookieName, boolean forceRefresh) {
        String msg = forceRefresh
                ? "🔄 Re-checking cookiesearch.org live for '" + cookieName + "'..."
                : "🌐 Fetching live definition from cookiesearch.org for '" + cookieName + "'...";
        statusIndicator.setText(msg);
        fetchLiveBtn.setEnabled(false);

        CookieSearchFetcher.fetchAsync(cookieName, forceRefresh, doc -> {
            fetchLiveBtn.setEnabled(true);
            if (doc != null && currentCookieName.equalsIgnoreCase(cookieName)) {
                this.currentDoc = doc;
                statusIndicator.setText("✓ Definition refreshed from cookiesearch.org.");
                renderDoc(doc);
            } else if (currentCookieName.equalsIgnoreCase(cookieName)) {
                statusIndicator.setText("Cookie not found in cookiesearch.org.");
            }
        });
    }

    private void renderDoc(CookieDocRecord doc) {
        if (doc == null) return;

        // Category Badge
        categoryBadge.setText(doc.category());
        categoryBadge.setBackground(doc.categoryColor());
        categoryBadge.setVisible(true);

        // Script Badge
        if (doc.hasScript()) {
            scriptBadge.setText("Script: " + doc.script());
            scriptBadge.setVisible(true);
        } else {
            scriptBadge.setVisible(false);
        }

        // Description
        explanationArea.setText(doc.description());
        explanationArea.setCaretPosition(0);

        // Related Cookies
        relatedContainer.removeAll();
        if (doc.hasRelated()) {
            relatedTitle.setVisible(true);
            relatedContainer.setVisible(true);
            for (String rel : doc.related()) {
                JButton relBtn = new JButton("🍪 " + rel);
                relBtn.setFont(relBtn.getFont().deriveFont(11f));
                relBtn.setMargin(new Insets(2, 6, 2, 6));
                relBtn.setToolTipText("View documentation for " + rel);
                relBtn.addActionListener(e -> setCookie(rel, currentSource));
                relatedContainer.add(relBtn);
            }
        } else {
            relatedTitle.setVisible(false);
            relatedContainer.setVisible(false);
        }

        revalidate();
        repaint();
    }

    private void resetView() {
        cookieNameLabel.setText("Select a cookie");
        categoryBadge.setVisible(false);
        sourceBadge.setVisible(false);
        scriptBadge.setVisible(false);
        fetchLiveBtn.setEnabled(false);
        copyLinkBtn.setEnabled(false);
        openBrowserBtn.setEnabled(false);
        statusIndicator.setText("");
        explanationArea.setText("Select a cookie from the table above to view its classification, purpose, and behavioral description from cookiesearch.org.");
        relatedTitle.setVisible(false);
        relatedContainer.removeAll();
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
}
