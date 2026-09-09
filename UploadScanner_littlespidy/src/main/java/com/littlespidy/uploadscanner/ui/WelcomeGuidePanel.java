package com.littlespidy.uploadscanner.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Visual onboarding and documentation panel for Upload Scanner.
 *
 * @author littlespidy
 */
public class WelcomeGuidePanel extends JPanel {

    public WelcomeGuidePanel() {
        super(new BorderLayout());
        setBorder(new EmptyBorder(16, 20, 16, 20));

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        // Header Title
        JLabel title = new JLabel("📤 Upload Scanner (Montoya Edition)");
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 20));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(title);

        JLabel subtitle = new JLabel("Comprehensive File Upload Security Testing, Visual ReDownloader & Execution Log Triage");
        subtitle.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        subtitle.setForeground(Color.GRAY);
        subtitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(subtitle);
        content.add(Box.createVerticalStrut(16));

        // Section 1: Workflow Overview
        content.add(createCard("🚀 How It Works",
                "<html><b>1. Select an Upload Request:</b> Right-click any HTTP file upload request across Burp (Proxy, Repeater, Logger) and choose <i>'Send to Upload Scanner'</i>.<br>" +
                        "<b>2. Configure the ReDownloader:</b> Specify where the uploaded file is stored. Use Start and End markers to parse dynamic URLs from the upload response, or define a static URL.<br>" +
                        "<b>3. Test ReDownloader:</b> Click <i>'🧪 Test ReDownloader'</i> to instantly verify URL extraction and see visual editor highlights.<br>" +
                        "<b>4. Launch the Scan:</b> Click <i>'▶ Start Scan'</i> to automatically test Web Shells, Polyglots, Path Traversal, and Extension Bypasses.<br>" +
                        "<b>5. Triage Results:</b> Monitor the <i>'Done Uploads'</i> activity log in real time with multi-select triage filters.</html>"));
        content.add(Box.createVerticalStrut(12));

        // Section 2: ReDownloader & Visual Markers
        content.add(createCard("🎯 ReDownloader & Visual Marker Highlights",
                "<html>The ReDownloader fetches the uploaded file to verify whether the server executed or exposed it.<br>" +
                        "<ul>" +
                        "<li><b>Start / End Markers:</b> Define delimiters surrounding the uploaded file URL in the response (e.g. <code>{\"url\":\"</code> and <code>\"}</code>).</li>" +
                        "<li><b>Placeholders:</b> Use <code>${FILENAME}</code>, <code>${FILENAME_NO_EXT}</code>, <code>${ORIG_EXT}</code>, and <code>${RANDOMIZE}</code> in markers, prefixes, or suffixes.</li>" +
                        "<li><b>Visual Highlighting:</b> When an entry is selected, Burp's message viewer automatically applies yellow/orange search highlighting to the exact extracted URL and matched tokens.</li>" +
                        "</ul></html>"));
        content.add(Box.createVerticalStrut(12));

        // Section 3: Done Uploads Log Triage
        content.add(createCard("📋 Enhanced Activity Log Triage",
                "<html>The modern <i>'Done Uploads'</i> activity log provides comprehensive oversight:<br>" +
                        "<ul>" +
                        "<li><b>Multi-Select Triage Buttons:</b> Instant popups to filter by <b>Stage</b> (Upload, Preflight, ReDownload), <b>Status</b> (2xx, 3xx, 4xx, 5xx), and <b>Method</b>.</li>" +
                        "<li><b>Live Search:</b> Filter entries instantly by target URL, payload filename, or status code.</li>" +
                        "<li><b>Master-Detail Inspection:</b> Click any row to view full request/response pairs in native Montoya editors.</li>" +
                        "<li><b>Export & Clear:</b> One-click <i>'🗑️ Clear Log'</i> and <i>'💾 Export TSV'</i> for offline reporting and sharing.</li>" +
                        "</ul></html>"));
        content.add(Box.createVerticalStrut(12));

        // Section 4: Attack Categories
        content.add(createCard("⚡ Supported Attack Vectors",
                "<html>" +
                        "<b>• Web Shells:</b> PHP system/phpinfo shells, PHTML, JSP Runtime execution, ASPX test files.<br>" +
                        "<b>• Image Polyglots:</b> Valid GIF89a headers and PNG IHDR chunks containing embedded PHP code to bypass strict magic-byte validation.<br>" +
                        "<b>• Path Traversal:</b> Directory climbing filenames (<code>../../shell.php</code>, <code>%2e%2e%2f</code>) to escape upload directories.<br>" +
                        "<b>• Extension & MIME Bypasses:</b> Double extensions (<code>.php.jpg</code>), case variations (<code>.PhP</code>), trailing dots (<code>.php.</code>), and null-bytes (<code>%00</code>).<br>" +
                        "<b>• Client-Side & AV:</b> Stored SVG XSS payloads and the standard EICAR anti-virus test file to check malware gateway inspection.</html>"));

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createCard(String title, String htmlBody) {
        JPanel card = new JPanel(new BorderLayout(6, 6));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 1, 1, 1, new Color(180, 180, 180, 70)),
                new EmptyBorder(10, 14, 10, 14)
        ));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lblTitle = new JLabel(title);
        lblTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        lblTitle.setForeground(new Color(0, 102, 204));
        card.add(lblTitle, BorderLayout.NORTH);

        JLabel lblContent = new JLabel(htmlBody);
        lblContent.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        card.add(lblContent, BorderLayout.CENTER);

        return card;
    }
}
