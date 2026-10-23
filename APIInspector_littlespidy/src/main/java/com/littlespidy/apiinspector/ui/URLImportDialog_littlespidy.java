// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.littlespidy.apiinspector.parser.APIParserFactory_littlespidy;
import com.littlespidy.apiinspector.parser.ParseResult_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Modal dialog allowing users to enter one or multiple URLs to fetch and import
 * API specifications (OpenAPI, Swagger, Postman collections).
 */
public class URLImportDialog_littlespidy extends JDialog {

    private final MontoyaApi api;
    private final List<ImportedCollection_littlespidy> importedCollections = new ArrayList<>();
    private final List<String> errors = new ArrayList<>();
    private boolean completed = false;

    private JTextArea urlTextArea;
    private JButton importButton;
    private JButton cancelButton;
    private JLabel statusLabel;
    private JProgressBar progressBar;

    public URLImportDialog_littlespidy(Window parent, MontoyaApi api) {
        super(parent, "Import API Definition from URL(s)", ModalityType.APPLICATION_MODAL);
        this.api = api;

        initComponents();
        pack();
        setLocationRelativeTo(parent);
    }

    private void initComponents() {
        JPanel contentPane = new JPanel(new BorderLayout(8, 8));
        contentPane.setBorder(new EmptyBorder(12, 12, 12, 12));

        JLabel instruction = new JLabel("Enter one or more API specification URLs (one per line):");
        instruction.setFont(instruction.getFont().deriveFont(Font.BOLD));
        contentPane.add(instruction, BorderLayout.NORTH);

        urlTextArea = new JTextArea(8, 45);
        urlTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        urlTextArea.setText("https://petstore.swagger.io/v2/swagger.json\n");
        JScrollPane scroll = new JScrollPane(urlTextArea);
        contentPane.add(scroll, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout(6, 6));

        JPanel progressPanel = new JPanel(new BorderLayout(4, 4));
        progressBar = new JProgressBar();
        progressBar.setVisible(false);
        statusLabel = new JLabel("Supported formats: OpenAPI 3.0/3.1, Swagger 2.0, Postman v2.x");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        progressPanel.add(statusLabel, BorderLayout.NORTH);
        progressPanel.add(progressBar, BorderLayout.SOUTH);
        bottomPanel.add(progressPanel, BorderLayout.CENTER);

        JPanel buttonBox = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        importButton = new JButton("Import URLs");
        importButton.setFont(importButton.getFont().deriveFont(Font.BOLD));
        importButton.addActionListener(e -> startImport());

        buttonBox.add(cancelButton);
        buttonBox.add(importButton);
        bottomPanel.add(buttonBox, BorderLayout.EAST);

        contentPane.add(bottomPanel, BorderLayout.SOUTH);
        setContentPane(contentPane);
    }

    private void startImport() {
        String text = urlTextArea.getText();
        if (text == null || text.isBlank()) {
            JOptionPane.showMessageDialog(this, "Please enter at least one URL.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String[] rawLines = text.split("\\r?\\n");
        List<String> validUrls = new ArrayList<>();
        for (String line : rawLines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
                errors.add("Invalid URL scheme (must be http:// or https://): " + trimmed);
                continue;
            }
            try {
                URI.create(trimmed);
                validUrls.add(trimmed);
            } catch (Exception e) {
                errors.add("Malformed URL: " + trimmed);
            }
        }

        if (validUrls.isEmpty() && !errors.isEmpty()) {
            JOptionPane.showMessageDialog(this, String.join("\n", errors), "URL Validation Errors", JOptionPane.ERROR_MESSAGE);
            return;
        }

        importButton.setEnabled(false);
        cancelButton.setEnabled(false);
        progressBar.setIndeterminate(false);
        progressBar.setMinimum(0);
        progressBar.setMaximum(validUrls.size());
        progressBar.setValue(0);
        progressBar.setVisible(true);

        Thread worker = new Thread(() -> {
            for (int i = 0; i < validUrls.size(); i++) {
                String targetUrl = validUrls.get(i);
                final int currentIdx = i + 1;
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Fetching (" + currentIdx + "/" + validUrls.size() + "): " + targetUrl);
                    progressBar.setValue(currentIdx);
                });

                try {
                    String content = fetchUrlContent(targetUrl);
                    ParseResult_littlespidy parseRes = APIParserFactory_littlespidy.parse(content, targetUrl, "URL");
                    if (parseRes.isSuccess() && parseRes.getCollection() != null) {
                        ImportedCollection_littlespidy col = parseRes.getCollection();
                        if (col.getTargetBaseUrl() == null || col.getTargetBaseUrl().isBlank()) {
                            col.setTargetBaseUrl(extractBaseFromUrl(targetUrl));
                        }
                        importedCollections.add(col);
                    } else {
                        errors.add("Error parsing " + targetUrl + ": " + parseRes.getErrorMessage());
                    }
                } catch (Exception ex) {
                    errors.add("Failed to fetch " + targetUrl + ": " + ex.getMessage());
                }
            }

            SwingUtilities.invokeLater(() -> {
                completed = true;
                if (!errors.isEmpty()) {
                    JOptionPane.showMessageDialog(this,
                            "Import finished with " + importedCollections.size() + " collection(s) imported and " + errors.size() + " issue(s):\n" +
                            String.join("\n", errors),
                            "Import Results",
                            importedCollections.isEmpty() ? JOptionPane.ERROR_MESSAGE : JOptionPane.WARNING_MESSAGE);
                }
                dispose();
            });
        }, "APIInspector-URLImporter");

        worker.setDaemon(true);
        worker.start();
    }

    private String fetchUrlContent(String urlStr) throws Exception {
        // First try Montoya HTTP client
        if (api != null && api.http() != null) {
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(urlStr);
                HttpRequestResponse reqResp = api.http().sendRequest(req);
                if (reqResp != null && reqResp.hasResponse()) {
                    return reqResp.response().bodyToString();
                }
            } catch (Exception ignored) {
            }
        }

        // Standard HttpURLConnection fallback
        URL url = URI.create(urlStr).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(15000);
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
        conn.setRequestProperty("Accept", "application/json, application/yaml, text/yaml, */*");

        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            throw new RuntimeException("HTTP response status " + code);
        }

        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    private String extractBaseFromUrl(String fullUrl) {
        try {
            URI uri = URI.create(fullUrl);
            String base = uri.getScheme() + "://" + uri.getHost();
            if (uri.getPort() > 0 && uri.getPort() != 80 && uri.getPort() != 443) {
                base += ":" + uri.getPort();
            }
            return base;
        } catch (Exception e) {
            return "";
        }
    }

    public boolean isCompleted() {
        return completed;
    }

    public List<ImportedCollection_littlespidy> getImportedCollections() {
        return importedCollections;
    }

    public List<String> getErrors() {
        return errors;
    }
}
