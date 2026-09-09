package com.littlespidy.uploadscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.uploadscanner.engine.MarkerHighlighter;
import com.littlespidy.uploadscanner.engine.ReDownloaderEngine;
import com.littlespidy.uploadscanner.engine.UploadScanExecutor;
import com.littlespidy.uploadscanner.model.ReDownloaderConfig;
import com.littlespidy.uploadscanner.model.StageType;
import com.littlespidy.uploadscanner.model.UploadEntry;
import com.littlespidy.uploadscanner.model.UploadScannerConfig;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Session tab for an individual upload request. Provides ReDownloader configuration,
 * visual marker preview, attack module selection, scan execution controls,
 * and live request/response editors.
 *
 * @author littlespidy
 */
public class UploadSessionPanel extends JPanel {

    private final MontoyaApi api;
    private final HttpRequest baseRequest;
    private final HttpResponse baseResponse;
    private final UploadScannerConfig config;
    private final Consumer<UploadEntry> logEntryConsumer;

    private JTextField preflightUrlField;
    private JTextField startMarkerField;
    private JTextField endMarkerField;
    private JTextField staticUrlField;
    private JTextField prefixField;
    private JTextField suffixField;
    private JCheckBox replaceBackslashCb;

    private JCheckBox webShellsCb;
    private JCheckBox polyglotsCb;
    private JCheckBox pathTraversalCb;
    private JCheckBox extensionBypassesCb;
    private JCheckBox svgXssCb;
    private JCheckBox eicarCb;
    private JSpinner throttleSpinner;

    private JButton testRedlBtn;
    private JButton startScanBtn;
    private JButton stopScanBtn;
    private JLabel statusLabel;
    private JLabel previewResultLabel;

    private HttpRequestEditor uploadReqEditor;
    private HttpResponseEditor uploadRespEditor;
    private HttpRequestEditor redlReqEditor;
    private HttpResponseEditor redlRespEditor;

    private UploadScanExecutor currentExecutor;

    public UploadSessionPanel(MontoyaApi api,
                              HttpRequest baseRequest,
                              HttpResponse baseResponse,
                              Consumer<UploadEntry> logEntryConsumer) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.baseRequest = baseRequest;
        this.baseResponse = baseResponse;
        this.config = new UploadScannerConfig();
        this.logEntryConsumer = logEntryConsumer;

        initUI();
    }

    private void initUI() {
        // ── Upper Controls (GridBagLayout) ──
        JPanel configContainer = new JPanel(new BorderLayout(4, 4));
        configContainer.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // ReDownloader Configuration Panel
        JPanel redlPanel = new JPanel(new GridBagLayout());
        redlPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "ReDownloader Options (Automatic Download of Uploaded Files)",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12)));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Preflight URL
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        redlPanel.add(new JLabel("Preflight URL:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; gbc.gridwidth = 3;
        preflightUrlField = new JTextField();
        preflightUrlField.setToolTipText("Optional URL to fetch before redownload (e.g. /profile/ or /gallery/)");
        redlPanel.add(preflightUrlField, gbc);

        // Row 1: Start Marker & End Marker
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0; gbc.gridwidth = 1;
        redlPanel.add(new JLabel("1. Start Marker:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 0.5;
        startMarkerField = new JTextField("{\"url\":\"", 16);
        startMarkerField.setToolTipText("Start delimiter of the URL in the response (supports ${FILENAME})");
        redlPanel.add(startMarkerField, gbc);

        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        redlPanel.add(new JLabel("End Marker:"), gbc);
        gbc.gridx = 3; gbc.gridy = 1; gbc.weightx = 0.5;
        endMarkerField = new JTextField("\"}", 16);
        endMarkerField.setToolTipText("End delimiter of the URL in the response (supports ${FILENAME})");
        redlPanel.add(endMarkerField, gbc);

        // Row 2: Prefix, Suffix, Replace Backslash
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        redlPanel.add(new JLabel("URL Prefix:"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 0.5;
        prefixField = new JTextField();
        prefixField.setToolTipText("Optional prefix prepended to extracted URL");
        redlPanel.add(prefixField, gbc);

        gbc.gridx = 2; gbc.gridy = 2; gbc.weightx = 0;
        redlPanel.add(new JLabel("URL Suffix:"), gbc);
        gbc.gridx = 3; gbc.gridy = 2; gbc.weightx = 0.5;
        suffixField = new JTextField();
        suffixField.setToolTipText("Optional suffix appended to extracted URL");
        redlPanel.add(suffixField, gbc);

        // Row 3: Static URL & Replace Backslash
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        redlPanel.add(new JLabel("2. Or Static URL:"), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 0.7; gbc.gridwidth = 2;
        staticUrlField = new JTextField();
        staticUrlField.setToolTipText("Static URL path (e.g. /uploads/${FILENAME})");
        redlPanel.add(staticUrlField, gbc);

        gbc.gridx = 3; gbc.gridy = 3; gbc.weightx = 0.3; gbc.gridwidth = 1;
        replaceBackslashCb = new JCheckBox("Replace \\/ with /", true);
        redlPanel.add(replaceBackslashCb, gbc);

        // Attack Categories & Execution Bar
        JPanel attackAndActionsPanel = new JPanel(new BorderLayout(4, 4));

        // Attack Modules Selection
        JPanel modulesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        modulesPanel.setBorder(BorderFactory.createTitledBorder("Attack Vectors"));
        webShellsCb = new JCheckBox("Web Shells", true);
        polyglotsCb = new JCheckBox("Image Polyglots", true);
        pathTraversalCb = new JCheckBox("Path Traversal", true);
        extensionBypassesCb = new JCheckBox("Extension Bypasses", true);
        svgXssCb = new JCheckBox("SVG XSS", true);
        eicarCb = new JCheckBox("EICAR AV", true);

        modulesPanel.add(webShellsCb);
        modulesPanel.add(polyglotsCb);
        modulesPanel.add(pathTraversalCb);
        modulesPanel.add(extensionBypassesCb);
        modulesPanel.add(svgXssCb);
        modulesPanel.add(eicarCb);

        modulesPanel.add(new JLabel("Delay (ms):"));
        throttleSpinner = new JSpinner(new SpinnerNumberModel(50, 0, 5000, 50));
        modulesPanel.add(throttleSpinner);

        // Action Buttons & Status
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
        testRedlBtn = new JButton("🧪 Test ReDownloader");
        testRedlBtn.setToolTipText("Parse the current response with configured markers and verify extraction");
        testRedlBtn.addActionListener(e -> testReDownloader());

        startScanBtn = new JButton("▶ Start Scan");
        startScanBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        startScanBtn.setForeground(new Color(0, 120, 50));
        startScanBtn.addActionListener(e -> startScan());

        stopScanBtn = new JButton("⏹ Stop");
        stopScanBtn.setEnabled(false);
        stopScanBtn.addActionListener(e -> stopScan());

        statusLabel = new JLabel("● Ready");
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        statusLabel.setForeground(Color.GRAY);

        previewResultLabel = new JLabel("");
        previewResultLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));

        actionsPanel.add(testRedlBtn);
        actionsPanel.add(startScanBtn);
        actionsPanel.add(stopScanBtn);
        actionsPanel.add(Box.createHorizontalStrut(10));
        actionsPanel.add(statusLabel);
        actionsPanel.add(Box.createHorizontalStrut(10));
        actionsPanel.add(previewResultLabel);

        attackAndActionsPanel.add(modulesPanel, BorderLayout.NORTH);
        attackAndActionsPanel.add(actionsPanel, BorderLayout.SOUTH);

        configContainer.add(redlPanel, BorderLayout.CENTER);
        configContainer.add(attackAndActionsPanel, BorderLayout.SOUTH);

        add(configContainer, BorderLayout.NORTH);

        // ── Lower Message Editors (Split Pane) ──
        uploadReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        uploadRespEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        redlReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        redlRespEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        uploadReqEditor.setRequest(baseRequest);
        if (baseResponse != null) {
            uploadRespEditor.setResponse(baseResponse);
        }

        JTabbedPane editorsTab = new JTabbedPane();
        editorsTab.addTab("📤 Upload Request", uploadReqEditor.uiComponent());
        editorsTab.addTab("📥 Upload Response", uploadRespEditor.uiComponent());
        editorsTab.addTab("🎯 ReDownload Request", redlReqEditor.uiComponent());
        editorsTab.addTab("🔍 ReDownload Response", redlRespEditor.uiComponent());

        add(editorsTab, BorderLayout.CENTER);
    }

    private void syncConfigFromUI() {
        ReDownloaderConfig rConfig = config.getRedownloaderConfig();
        rConfig.setPreflightUrl(preflightUrlField.getText().trim());
        rConfig.setStartMarker(startMarkerField.getText().trim());
        rConfig.setEndMarker(endMarkerField.getText().trim());
        rConfig.setStaticUrl(staticUrlField.getText().trim());
        rConfig.setUrlPrefix(prefixField.getText().trim());
        rConfig.setUrlSuffix(suffixField.getText().trim());
        rConfig.setReplaceBackslash(replaceBackslashCb.isSelected());

        config.setTestWebShells(webShellsCb.isSelected());
        config.setTestPolyglots(polyglotsCb.isSelected());
        config.setTestPathTraversal(pathTraversalCb.isSelected());
        config.setTestExtensionBypasses(extensionBypassesCb.isSelected());
        config.setTestSvgXss(svgXssCb.isSelected());
        config.setTestEicar(eicarCb.isSelected());
        config.setThrottleMs((Integer) throttleSpinner.getValue());
    }

    private void testReDownloader() {
        syncConfigFromUI();
        if (baseResponse == null) {
            previewResultLabel.setText("No base response available to test.");
            previewResultLabel.setForeground(Color.RED);
            return;
        }

        ReDownloaderEngine engine = new ReDownloaderEngine(api, config.getRedownloaderConfig());
        String responseStr = baseResponse.bodyToString();
        MarkerHighlighter.ExtractionResult extraction = engine.parseDownloadUrl(responseStr, "test_file.png");

        if (extraction.isFound()) {
            String extractedUrl = extraction.getExtractedText();
            previewResultLabel.setText(String.format("✔ Extracted: %s (Offsets: %d..%d)",
                    extractedUrl, extraction.getContentStartOffset(), extraction.getContentEndOffset()));
            previewResultLabel.setForeground(new Color(0, 130, 40));

            // Automatically highlight the extracted URL in the Upload Response viewer
            uploadRespEditor.setSearchExpression(extractedUrl);

            // Construct and display the simulated ReDownload request
            HttpRequest redlReq = engine.buildRedownloadRequest(baseRequest, extractedUrl);
            if (redlReq != null) {
                redlReqEditor.setRequest(redlReq);
            }
        } else {
            previewResultLabel.setText("❌ Delimiters not found in current response. Check markers!");
            previewResultLabel.setForeground(Color.RED);
        }
    }

    private void startScan() {
        syncConfigFromUI();
        startScanBtn.setEnabled(false);
        stopScanBtn.setEnabled(true);
        testRedlBtn.setEnabled(false);

        currentExecutor = new UploadScanExecutor(
                api,
                config,
                entry -> {
                    // Forward to global activity log
                    logEntryConsumer.accept(entry);

                    // Update local editors for the most recent message
                    if (entry.getStage() == StageType.UPLOAD) {
                        uploadReqEditor.setRequest(entry.getRequestResponse().request());
                        if (entry.getRequestResponse().hasResponse()) {
                            uploadRespEditor.setResponse(entry.getRequestResponse().response());
                            if (!entry.getExtractedMarkerText().isEmpty()) {
                                uploadRespEditor.setSearchExpression(entry.getExtractedMarkerText());
                            }
                        }
                    } else if (entry.getStage() == StageType.REDOWNLOAD) {
                        redlReqEditor.setRequest(entry.getRequestResponse().request());
                        if (entry.getRequestResponse().hasResponse()) {
                            redlRespEditor.setResponse(entry.getRequestResponse().response());
                            if (!entry.getExtractedMarkerText().isEmpty()) {
                                redlRespEditor.setSearchExpression(entry.getExtractedMarkerText());
                            }
                        }
                    }
                },
                status -> SwingUtilities.invokeLater(() -> statusLabel.setText("● " + status)),
                () -> SwingUtilities.invokeLater(() -> {
                    startScanBtn.setEnabled(true);
                    stopScanBtn.setEnabled(false);
                    testRedlBtn.setEnabled(true);
                    statusLabel.setText("● Completed");
                    statusLabel.setForeground(new Color(0, 140, 50));
                })
        );

        statusLabel.setForeground(new Color(0, 100, 200));
        currentExecutor.startScan(baseRequest);
    }

    private void stopScan() {
        if (currentExecutor != null) {
            currentExecutor.stop();
            statusLabel.setText("● Stopped");
            statusLabel.setForeground(Color.RED);
            startScanBtn.setEnabled(true);
            stopScanBtn.setEnabled(false);
            testRedlBtn.setEnabled(true);
        }
    }

    public void cleanup() {
        if (currentExecutor != null) {
            currentExecutor.stop();
        }
    }
}
