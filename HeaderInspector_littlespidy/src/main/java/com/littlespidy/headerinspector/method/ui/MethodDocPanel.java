// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.method.ui;

import com.littlespidy.headerinspector.method.knowledge.HttpDevMethodDoc;
import com.littlespidy.headerinspector.method.knowledge.HttpDevMethodKnowledgeBase;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated documentation and reference panel for HTTP methods,
 * embedding the exact explanations, properties (Safe, Idempotent, Cacheable),
 * and official RFC specifications scraped from https://http.dev.
 *
 * @author littlespidy
 */
public class MethodDocPanel extends JPanel {

    private final JLabel methodNameLabel = new JLabel("Select an HTTP method");
    private final JLabel safeBadge = new JLabel("Safe");
    private final JLabel idempotentBadge = new JLabel("Idempotent");
    private final JLabel cacheableBadge = new JLabel("Cacheable");
    private final JButton copyLinkBtn = new JButton("Copy Link");
    private final JButton openBrowserBtn = new JButton("Open in Browser");

    private final JLabel summaryLabel = new JLabel("Select an HTTP method from the table above to view its exact documentation from http.dev.");
    private final JPanel summaryCard = new JPanel(new BorderLayout(5, 5));

    private final JPanel propertiesContainer = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

    private final JTextArea explanationArea = new JTextArea();

    private final JPanel specsContainer = new JPanel();
    private final JLabel specsTitle = new JLabel("Official Specifications & Standards:");

    private HttpDevMethodDoc currentDoc = null;
    private String currentMethodName = "";

    public MethodDocPanel() {
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

        methodNameLabel.setFont(methodNameLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleAndBadges.add(methodNameLabel);

        styleBadge(safeBadge, new Color(46, 204, 113), Color.WHITE);
        styleBadge(idempotentBadge, new Color(52, 152, 219), Color.WHITE);
        styleBadge(cacheableBadge, new Color(155, 89, 182), Color.WHITE);
        safeBadge.setVisible(false);
        idempotentBadge.setVisible(false);
        cacheableBadge.setVisible(false);

        titleAndBadges.add(safeBadge);
        titleAndBadges.add(idempotentBadge);
        titleAndBadges.add(cacheableBadge);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        actions.setOpaque(false);

        copyLinkBtn.setToolTipText("Copy reference URL to clipboard");
        openBrowserBtn.setToolTipText("Open method documentation in default web browser");
        copyLinkBtn.setEnabled(false);
        openBrowserBtn.setEnabled(false);

        copyLinkBtn.addActionListener(e -> {
            String url = (currentDoc != null) ? currentDoc.referenceUrl() : "https://http.dev/methods";
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
            JOptionPane.showMessageDialog(this, "Copied to clipboard:\n" + url, "Reference Copied", JOptionPane.INFORMATION_MESSAGE);
        });

        openBrowserBtn.addActionListener(e -> {
            String url = (currentDoc != null) ? currentDoc.referenceUrl() : "https://http.dev/methods";
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
        explanationScroll.setBorder(BorderFactory.createTitledBorder("Method Semantics & Behavior (http.dev)"));
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

    public void setMethod(String methodName) {
        this.currentMethodName = (methodName != null) ? methodName.trim() : "";
        if (currentMethodName.isEmpty()) {
            resetView();
            return;
        }

        this.currentDoc = HttpDevMethodKnowledgeBase.get(currentMethodName);
        methodNameLabel.setText(currentMethodName);

        if (currentDoc != null) {
            safeBadge.setText("Safe: " + (currentDoc.safe() ? "Yes" : "No"));
            styleBadge(safeBadge, currentDoc.safe() ? new Color(46, 204, 113) : new Color(231, 76, 60), Color.WHITE);
            safeBadge.setVisible(true);

            idempotentBadge.setText("Idempotent: " + (currentDoc.idempotent() ? "Yes" : "No"));
            styleBadge(idempotentBadge, currentDoc.idempotent() ? new Color(52, 152, 219) : new Color(230, 126, 34), Color.WHITE);
            idempotentBadge.setVisible(true);

            cacheableBadge.setText("Cacheable: " + currentDoc.cacheable());
            styleBadge(cacheableBadge, currentDoc.cacheable().equalsIgnoreCase("Yes") ? new Color(155, 89, 182) : new Color(127, 140, 141), Color.WHITE);
            cacheableBadge.setVisible(true);

            copyLinkBtn.setEnabled(true);
            openBrowserBtn.setEnabled(true);

            summaryLabel.setText("<html><b>Summary:</b> " + escapeHtml(currentDoc.summary()) + "</html>");
            explanationArea.setText(currentDoc.explanation());
            explanationArea.setCaretPosition(0);

            specsContainer.removeAll();
            if (currentDoc.hasSpecifications()) {
                specsTitle.setVisible(true);
                for (HttpDevMethodDoc.Specification spec : currentDoc.specifications()) {
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
            safeBadge.setVisible(false);
            idempotentBadge.setVisible(false);
            cacheableBadge.setVisible(false);
            copyLinkBtn.setEnabled(false);
            openBrowserBtn.setEnabled(false);

            summaryLabel.setText("<html><i>Method '" + escapeHtml(currentMethodName) + "' is not present in standard http.dev reference (Custom or proprietary verb).</i></html>");
            explanationArea.setText("No official http.dev documentation available for method '" + currentMethodName + "'.\n" +
                    "This method may be an application-specific custom action or an uncommon protocol extension.");
            explanationArea.setCaretPosition(0);
            specsContainer.removeAll();
            specsTitle.setVisible(false);
        }

        revalidate();
        repaint();
    }

    public void resetView() {
        this.currentDoc = null;
        this.currentMethodName = "";
        methodNameLabel.setText("Select an HTTP method");
        safeBadge.setVisible(false);
        idempotentBadge.setVisible(false);
        cacheableBadge.setVisible(false);
        copyLinkBtn.setEnabled(false);
        openBrowserBtn.setEnabled(false);
        summaryLabel.setText("Select an HTTP method from the table above to view its exact documentation from http.dev.");
        explanationArea.setText("");
        specsContainer.removeAll();
        specsTitle.setVisible(false);
        revalidate();
        repaint();
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
