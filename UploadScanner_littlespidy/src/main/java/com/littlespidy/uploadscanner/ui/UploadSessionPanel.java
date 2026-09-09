package com.littlespidy.uploadscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
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
import java.util.Optional;
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

    // ReDownloader Wizard Controls
    private JButton autoDetectBtn;
    private JLabel autoDetectResultLabel;

    private JButton useSelectionBtn;
    private JLabel useSelectionResultLabel;

    private JTextField staticUrlField;
    private JTextField startMarkerField;
    private JTextField endMarkerField;
    private JTextField prefixField;
    private JTextField suffixField;
    private JTextField preflightUrlField;
    private JCheckBox replaceBackslashCb;

    // 24 Attack Vector Checkboxes across 5 Categories
    // Category 1: Server RCE
    private JCheckBox phpCb;
    private JCheckBox jspCb;
    private JCheckBox aspCb;
    private JCheckBox htaccessCb;
    private JCheckBox webConfigCb;
    private JCheckBox cgiCb;
    private JCheckBox ssiEsiCb;

    // Category 2: Image Libraries
    private JCheckBox imageTragickCb;
    private JCheckBox magickDelegatesCb;
    private JCheckBox ghostscriptCb;
    private JCheckBox libavformatCb;

    // Category 3: XML & Documents
    private JCheckBox xxeSvgCb;
    private JCheckBox xxeXmlCb;
    private JCheckBox xxeOfficeCb;
    private JCheckBox xxeXmpCb;
    private JCheckBox pdfInjectionsCb;
    private JCheckBox csvFormulaCb;

    // Category 4: Client-Side & Polyglots
    private JCheckBox xssHtmlCb;
    private JCheckBox xssSvgCb;
    private JCheckBox xssSwfCb;
    private JCheckBox polyglotJpegCb;
    private JCheckBox polyglotGifCb;

    // Category 5: Archives, Quirks & DoS
    private JCheckBox zipSlipCb;
    private JCheckBox tarSymlinkCb;
    private JCheckBox uploadQuirksCb;
    private JCheckBox eicarCb;
    private JCheckBox pixelFloodCb;
    private JCheckBox billionLaughsCb;

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
        JPanel configContainer = new JPanel(new BorderLayout(6, 6));
        configContainer.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // ── 1. ReDownloader Help Explainer Banner ──
        JPanel bannerPanel = new JPanel(new BorderLayout(6, 4));
        bannerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(180, 210, 240), 1),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        bannerPanel.setBackground(new Color(242, 248, 255));
        JLabel bannerTitle = new JLabel("💡 What is ReDownloader and Why Do You Need It?");
        bannerTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        bannerTitle.setForeground(new Color(0, 80, 160));

        JLabel bannerDesc = new JLabel("<html><b>Uploading</b> a payload only tells you if the server accepted the file. " +
                "To verify if code actually executed (e.g. <code>phpinfo()</code> or whoami) or if SVG XSS reflected, Burp must <b>re-download</b> the file from the web server. " +
                "Choose one of the 3 simple modes below to tell the scanner where to find the uploaded file:</html>");
        bannerDesc.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        bannerPanel.add(bannerTitle, BorderLayout.NORTH);
        bannerPanel.add(bannerDesc, BorderLayout.CENTER);

        // ── 2. ReDownloader Wizard Modes (Tabbed) ──
        JTabbedPane redlTabs = new JTabbedPane();
        redlTabs.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));

        // Mode 1: ✨ Magic Auto-Detect (Recommended)
        JPanel autoDetectPanel = new JPanel(new BorderLayout(8, 8));
        autoDetectPanel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        JPanel autoTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        autoDetectBtn = new JButton("✨ Auto-Detect Download URL from Response");
        autoDetectBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        autoDetectBtn.setBackground(new Color(230, 245, 230));
        autoDetectBtn.addActionListener(e -> autoDetectDownloadUrl());

        replaceBackslashCb = new JCheckBox("Replace \\/ with / (unescape JSON slashes)", true);
        autoTop.add(autoDetectBtn);
        autoTop.add(replaceBackslashCb);

        autoDetectResultLabel = new JLabel("Click 'Auto-Detect' to automatically parse JSON keys ('url', 'path', 'file'), HTML tags, or redirects.");
        autoDetectResultLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        autoDetectResultLabel.setForeground(Color.GRAY);

        autoDetectPanel.add(autoTop, BorderLayout.NORTH);
        autoDetectPanel.add(autoDetectResultLabel, BorderLayout.CENTER);
        redlTabs.addTab("✨ 1. Magic Auto-Detect", autoDetectPanel);

        // Mode 2: 🎯 1-Click Selection Helper
        JPanel selectionPanel = new JPanel(new BorderLayout(8, 8));
        selectionPanel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        JPanel selTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        useSelectionBtn = new JButton("🎯 Use Highlighted Text as Download URL");
        useSelectionBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        useSelectionBtn.addActionListener(e -> useSelectionAsDownloadUrl());
        selTop.add(useSelectionBtn);

        useSelectionResultLabel = new JLabel("Highlight the file URL inside the 'Upload Response' editor below, then click this button.");
        useSelectionResultLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        useSelectionResultLabel.setForeground(Color.GRAY);

        selectionPanel.add(selTop, BorderLayout.NORTH);
        selectionPanel.add(useSelectionResultLabel, BorderLayout.CENTER);
        redlTabs.addTab("🎯 2. 1-Click Highlight Helper", selectionPanel);

        // Mode 3: 📁 Common Directory Presets
        JPanel presetsPanel = new JPanel(new BorderLayout(6, 6));
        presetsPanel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        JPanel presetButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        presetButtons.add(new JLabel("Quick Presets:"));

        String[] samplePresets = {
                "/uploads/${FILENAME}",
                "/static/${FILENAME}",
                "/media/${FILENAME}",
                "/files/${FILENAME}",
                "/images/${FILENAME}",
                "/upload/${FILENAME}"
        };

        staticUrlField = new JTextField("/uploads/${FILENAME}", 25);
        for (String preset : samplePresets) {
            JButton pb = new JButton(preset);
            pb.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            pb.addActionListener(e -> {
                staticUrlField.setText(preset);
                syncConfigFromUI();
                previewResultLabel.setText("Target set: " + preset);
                previewResultLabel.setForeground(new Color(0, 120, 40));
            });
            presetButtons.add(pb);
        }

        JPanel staticInputRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        staticInputRow.add(new JLabel("Target Static URL Pattern:"));
        staticInputRow.add(staticUrlField);
        staticInputRow.add(new JLabel("(supports ${FILENAME}, ${FILENAME_NO_EXT}, ${RANDOMIZE})"));

        presetsPanel.add(presetButtons, BorderLayout.NORTH);
        presetsPanel.add(staticInputRow, BorderLayout.CENTER);
        redlTabs.addTab("📁 3. Directory Presets", presetsPanel);

        // Mode 4: ⚙️ Advanced Custom Markers
        JPanel advancedPanel = new JPanel(new GridBagLayout());
        advancedPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 4, 2, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        advancedPanel.add(new JLabel("Start Marker:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.5;
        startMarkerField = new JTextField("{\"url\":\"", 14);
        advancedPanel.add(startMarkerField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        advancedPanel.add(new JLabel("End Marker:"), gbc);
        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0.5;
        endMarkerField = new JTextField("\"}", 14);
        advancedPanel.add(endMarkerField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        advancedPanel.add(new JLabel("URL Prefix:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 0.5;
        prefixField = new JTextField(14);
        advancedPanel.add(prefixField, gbc);

        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        advancedPanel.add(new JLabel("URL Suffix:"), gbc);
        gbc.gridx = 3; gbc.gridy = 1; gbc.weightx = 0.5;
        suffixField = new JTextField(14);
        advancedPanel.add(suffixField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        advancedPanel.add(new JLabel("Preflight URL:"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0; gbc.gridwidth = 3;
        preflightUrlField = new JTextField();
        preflightUrlField.setToolTipText("Optional URL to fetch before redownload (e.g. /profile/)");
        advancedPanel.add(preflightUrlField, gbc);

        redlTabs.addTab("⚙️ 4. Advanced Markers", advancedPanel);

        // ── 3. Categorized Attack Vectors (5 Tabs) ──
        JTabbedPane attackTabs = new JTabbedPane();
        attackTabs.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));

        // Tab 1: Server RCE
        JPanel rcePanel = new JPanel(new BorderLayout(4, 4));
        JPanel rceChecks = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        phpCb = new JCheckBox("PHP Shells & Bypasses", true);
        jspCb = new JCheckBox("JSP / JSPX", true);
        aspCb = new JCheckBox("ASP / ASPX", true);
        htaccessCb = new JCheckBox("Apache .htaccess", true);
        webConfigCb = new JCheckBox("IIS web.config", true);
        cgiCb = new JCheckBox("CGI Scripts (Perl/Python/Sh)", true);
        ssiEsiCb = new JCheckBox("SSI & ESI", true);

        rceChecks.add(phpCb);
        rceChecks.add(jspCb);
        rceChecks.add(aspCb);
        rceChecks.add(htaccessCb);
        rceChecks.add(webConfigCb);
        rceChecks.add(cgiCb);
        rceChecks.add(ssiEsiCb);

        JPanel rceActions = createCategoryActionToolbar(List.of(phpCb, jspCb, aspCb, htaccessCb, webConfigCb, cgiCb, ssiEsiCb));
        rcePanel.add(rceChecks, BorderLayout.CENTER);
        rcePanel.add(rceActions, BorderLayout.EAST);
        attackTabs.addTab("💻 Server RCE", rcePanel);

        // Tab 2: Image Libraries
        JPanel imgPanel = new JPanel(new BorderLayout(4, 4));
        JPanel imgChecks = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        imageTragickCb = new JCheckBox("ImageTragick (CVE-2016-3714)", true);
        magickDelegatesCb = new JCheckBox("Magick Delegates", true);
        ghostscriptCb = new JCheckBox("Ghostscript (CVE-2018-16509)", true);
        libavformatCb = new JCheckBox("LibAVFormat SSRF", true);

        imgChecks.add(imageTragickCb);
        imgChecks.add(magickDelegatesCb);
        imgChecks.add(ghostscriptCb);
        imgChecks.add(libavformatCb);

        JPanel imgActions = createCategoryActionToolbar(List.of(imageTragickCb, magickDelegatesCb, ghostscriptCb, libavformatCb));
        imgPanel.add(imgChecks, BorderLayout.CENTER);
        imgPanel.add(imgActions, BorderLayout.EAST);
        attackTabs.addTab("🖼️ Image Libraries", imgPanel);

        // Tab 3: XML & Documents
        JPanel docPanel = new JPanel(new BorderLayout(4, 4));
        JPanel docChecks = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        xxeSvgCb = new JCheckBox("SVG XXE", true);
        xxeXmlCb = new JCheckBox("XML XXE", true);
        xxeOfficeCb = new JCheckBox("Office DOCX XXE", true);
        xxeXmpCb = new JCheckBox("XMP Metadata XXE", true);
        pdfInjectionsCb = new JCheckBox("PDF Actions & JavaScript", true);
        csvFormulaCb = new JCheckBox("CSV Formula Injection", true);

        docChecks.add(xxeSvgCb);
        docChecks.add(xxeXmlCb);
        docChecks.add(xxeOfficeCb);
        docChecks.add(xxeXmpCb);
        docChecks.add(pdfInjectionsCb);
        docChecks.add(csvFormulaCb);

        JPanel docActions = createCategoryActionToolbar(List.of(xxeSvgCb, xxeXmlCb, xxeOfficeCb, xxeXmpCb, pdfInjectionsCb, csvFormulaCb));
        docPanel.add(docChecks, BorderLayout.CENTER);
        docPanel.add(docActions, BorderLayout.EAST);
        attackTabs.addTab("📄 XML & Documents", docPanel);

        // Tab 4: Client-Side & Polyglots
        JPanel clientPanel = new JPanel(new BorderLayout(4, 4));
        JPanel clientChecks = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        xssHtmlCb = new JCheckBox("HTML Stored XSS", true);
        xssSvgCb = new JCheckBox("SVG Stored XSS", true);
        xssSwfCb = new JCheckBox("Flash SWF", true);
        polyglotJpegCb = new JCheckBox("JPEG+JS CSP Polyglot", true);
        polyglotGifCb = new JCheckBox("GIF+JS CSP Polyglot", true);

        clientChecks.add(xssHtmlCb);
        clientChecks.add(xssSvgCb);
        clientChecks.add(xssSwfCb);
        clientChecks.add(polyglotJpegCb);
        clientChecks.add(polyglotGifCb);

        JPanel clientActions = createCategoryActionToolbar(List.of(xssHtmlCb, xssSvgCb, xssSwfCb, polyglotJpegCb, polyglotGifCb));
        clientPanel.add(clientChecks, BorderLayout.CENTER);
        clientPanel.add(clientActions, BorderLayout.EAST);
        attackTabs.addTab("🌐 Client-Side & Polyglots", clientPanel);

        // Tab 5: Archives, Quirks & DoS
        JPanel archPanel = new JPanel(new BorderLayout(4, 4));
        JPanel archChecks = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        zipSlipCb = new JCheckBox("Zip Slip (Traversal in ZIP)", true);
        tarSymlinkCb = new JCheckBox("TAR Symlink (/etc/passwd)", true);
        uploadQuirksCb = new JCheckBox("Upload Quirks (dots, nulls)", true);
        eicarCb = new JCheckBox("EICAR AV Test", true);
        pixelFloodCb = new JCheckBox("DoS: Pixel Flood", false);
        billionLaughsCb = new JCheckBox("DoS: Billion Laughs", false);

        archChecks.add(zipSlipCb);
        archChecks.add(tarSymlinkCb);
        archChecks.add(uploadQuirksCb);
        archChecks.add(eicarCb);
        archChecks.add(pixelFloodCb);
        archChecks.add(billionLaughsCb);

        JPanel archActions = createCategoryActionToolbar(List.of(zipSlipCb, tarSymlinkCb, uploadQuirksCb, eicarCb, pixelFloodCb, billionLaughsCb));
        archPanel.add(archChecks, BorderLayout.CENTER);
        archPanel.add(archActions, BorderLayout.EAST);
        attackTabs.addTab("⚙️ Archives, Quirks & DoS", archPanel);

        // ── 4. Live Action & Status Toolbar ──
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
        testRedlBtn = new JButton("🧪 Test ReDownloader Now");
        testRedlBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        testRedlBtn.setToolTipText("Verify URL extraction and test downloading the file from the server");
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
        previewResultLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));

        actionsPanel.add(testRedlBtn);
        actionsPanel.add(startScanBtn);
        actionsPanel.add(stopScanBtn);
        actionsPanel.add(new JLabel("Delay (ms):"));
        throttleSpinner = new JSpinner(new SpinnerNumberModel(50, 0, 5000, 50));
        actionsPanel.add(throttleSpinner);
        actionsPanel.add(Box.createHorizontalStrut(10));
        actionsPanel.add(statusLabel);
        actionsPanel.add(Box.createHorizontalStrut(10));
        actionsPanel.add(previewResultLabel);

        // Assemble Top
        JPanel midPanel = new JPanel(new BorderLayout(4, 4));
        midPanel.add(redlTabs, BorderLayout.NORTH);
        midPanel.add(attackTabs, BorderLayout.CENTER);

        configContainer.add(bannerPanel, BorderLayout.NORTH);
        configContainer.add(midPanel, BorderLayout.CENTER);
        configContainer.add(actionsPanel, BorderLayout.SOUTH);

        add(configContainer, BorderLayout.NORTH);

        // ── 5. Lower Message Editors (Split Pane) ──
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

        // Auto-run detection at initial load if response exists
        if (baseResponse != null) {
            SwingUtilities.invokeLater(this::autoDetectDownloadUrl);
        }
    }

    private JPanel createCategoryActionToolbar(List<JCheckBox> boxes) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 2));
        JButton selAll = new JButton("Select All");
        selAll.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        selAll.addActionListener(e -> boxes.forEach(b -> b.setSelected(true)));

        JButton clearAll = new JButton("Clear");
        clearAll.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        clearAll.addActionListener(e -> boxes.forEach(b -> b.setSelected(false)));

        bar.add(selAll);
        bar.add(clearAll);
        return bar;
    }

    private void autoDetectDownloadUrl() {
        if (baseResponse == null) {
            autoDetectResultLabel.setText("No upload response available to analyze.");
            autoDetectResultLabel.setForeground(Color.RED);
            return;
        }

        ReDownloaderEngine engine = new ReDownloaderEngine(api, config.getRedownloaderConfig());
        String uploadedFilename = extractFilename(baseRequest);
        ReDownloaderEngine.DetectionResult result = engine.autoDetectDownloadUrl(baseResponse, uploadedFilename);

        if (result.isFound()) {
            autoDetectResultLabel.setText("✔ " + result.getReason() + ": " + result.getDetectedUrl());
            autoDetectResultLabel.setForeground(new Color(0, 130, 40));

            if (!result.getSuggestedStartMarker().isEmpty()) {
                startMarkerField.setText(result.getSuggestedStartMarker());
            }
            if (!result.getSuggestedEndMarker().isEmpty()) {
                endMarkerField.setText(result.getSuggestedEndMarker());
            }

            previewResultLabel.setText("✔ Detected Target: " + result.getDetectedUrl());
            previewResultLabel.setForeground(new Color(0, 130, 40));

            uploadRespEditor.setSearchExpression(result.getDetectedUrl());

            HttpRequest testReq = engine.buildRedownloadRequest(baseRequest, result.getDetectedUrl());
            if (testReq != null) {
                redlReqEditor.setRequest(testReq);
            }
        } else {
            autoDetectResultLabel.setText("❌ " + result.getReason() + " (Use 1-Click Highlight or Directory Presets)");
            autoDetectResultLabel.setForeground(Color.RED);
        }
    }

    private void useSelectionAsDownloadUrl() {
        if (uploadRespEditor == null || baseResponse == null) {
            useSelectionResultLabel.setText("No response available.");
            useSelectionResultLabel.setForeground(Color.RED);
            return;
        }

        Optional<Selection> selOpt = uploadRespEditor.selection();
        if (selOpt.isEmpty()) {
            useSelectionResultLabel.setText("⚠️ Please highlight the URL text in the 'Upload Response' editor below first.");
            useSelectionResultLabel.setForeground(Color.ORANGE.darker());
            return;
        }

        Selection sel = selOpt.get();
        String fullBody = baseResponse.bodyToString();
        int selStart = sel.offsets().startIndexInclusive();
        int selEnd = sel.offsets().endIndexExclusive();

        String selectedStr = sel.contents().toString();
        if (selectedStr.trim().isEmpty()) {
            useSelectionResultLabel.setText("⚠️ Highlighted text is empty.");
            useSelectionResultLabel.setForeground(Color.ORANGE.darker());
            return;
        }

        ReDownloaderEngine engine = new ReDownloaderEngine(api, config.getRedownloaderConfig());
        ReDownloaderEngine.DetectionResult det = engine.deriveMarkersFromSelection(fullBody, selStart, selEnd);

        if (det.isFound()) {
            startMarkerField.setText(det.getSuggestedStartMarker());
            endMarkerField.setText(det.getSuggestedEndMarker());
            useSelectionResultLabel.setText("✔ Set Markers! Start: '" + det.getSuggestedStartMarker() + "' | End: '" + det.getSuggestedEndMarker() + "'");
            useSelectionResultLabel.setForeground(new Color(0, 130, 40));

            previewResultLabel.setText("✔ Selection Target: " + det.getDetectedUrl());
            previewResultLabel.setForeground(new Color(0, 130, 40));

            uploadRespEditor.setSearchExpression(det.getDetectedUrl());

            HttpRequest testReq = engine.buildRedownloadRequest(baseRequest, det.getDetectedUrl());
            if (testReq != null) {
                redlReqEditor.setRequest(testReq);
            }
        } else {
            useSelectionResultLabel.setText("❌ " + det.getReason());
            useSelectionResultLabel.setForeground(Color.RED);
        }
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

        // Category 1
        config.setTestPhp(phpCb.isSelected());
        config.setTestJsp(jspCb.isSelected());
        config.setTestAsp(aspCb.isSelected());
        config.setTestHtaccess(htaccessCb.isSelected());
        config.setTestWebConfig(webConfigCb.isSelected());
        config.setTestCgi(cgiCb.isSelected());
        config.setTestSsiEsi(ssiEsiCb.isSelected());

        // Category 2
        config.setTestImageTragick(imageTragickCb.isSelected());
        config.setTestMagickDelegates(magickDelegatesCb.isSelected());
        config.setTestGhostscript(ghostscriptCb.isSelected());
        config.setTestLibavformat(libavformatCb.isSelected());

        // Category 3
        config.setTestXxeSvg(xxeSvgCb.isSelected());
        config.setTestXxeXml(xxeXmlCb.isSelected());
        config.setTestXxeOffice(xxeOfficeCb.isSelected());
        config.setTestXxeXmp(xxeXmpCb.isSelected());
        config.setTestPdfInjections(pdfInjectionsCb.isSelected());
        config.setTestCsvFormula(csvFormulaCb.isSelected());

        // Category 4
        config.setTestXssHtml(xssHtmlCb.isSelected());
        config.setTestXssSvg(xssSvgCb.isSelected());
        config.setTestXssSwf(xssSwfCb.isSelected());
        config.setTestPolyglotJpeg(polyglotJpegCb.isSelected());
        config.setTestPolyglotGif(polyglotGifCb.isSelected());

        // Category 5
        config.setTestZipSlip(zipSlipCb.isSelected());
        config.setTestTarSymlink(tarSymlinkCb.isSelected());
        config.setTestUploadQuirks(uploadQuirksCb.isSelected());
        config.setTestEicar(eicarCb.isSelected());
        config.setTestPixelFlood(pixelFloodCb.isSelected());
        config.setTestBillionLaughs(billionLaughsCb.isSelected());

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
        String testFilename = extractFilename(baseRequest);
        MarkerHighlighter.ExtractionResult extraction = engine.parseDownloadUrl(responseStr, testFilename);

        if (!extraction.isFound()) {
            ReDownloaderEngine.DetectionResult auto = engine.autoDetectDownloadUrl(baseResponse, testFilename);
            if (auto.isFound()) {
                extraction = new MarkerHighlighter.ExtractionResult(true, auto.getDetectedUrl(), 0, 0, 0, auto.getDetectedUrl().length());
            }
        }

        if (extraction.isFound()) {
            String targetUrl = extraction.getExtractedText();
            previewResultLabel.setText("Testing GET: " + targetUrl + " ...");
            previewResultLabel.setForeground(new Color(0, 100, 180));

            uploadRespEditor.setSearchExpression(targetUrl);

            HttpRequest redlReq = engine.buildRedownloadRequest(baseRequest, targetUrl);
            if (redlReq != null) {
                redlReqEditor.setRequest(redlReq);
                new Thread(() -> {
                    HttpRequestResponse respPair = engine.executeRedownload(redlReq, "");
                    SwingUtilities.invokeLater(() -> {
                        if (respPair != null && respPair.hasResponse()) {
                            redlRespEditor.setResponse(respPair.response());
                            previewResultLabel.setText(String.format("✔ HTTP %d (%d bytes) - Download Verified!",
                                    respPair.response().statusCode(), respPair.response().body().length()));
                            previewResultLabel.setForeground(new Color(0, 130, 40));
                        } else {
                            previewResultLabel.setText("⚠️ Request sent but no response received.");
                            previewResultLabel.setForeground(Color.ORANGE.darker());
                        }
                    });
                }).start();
            }
        } else {
            previewResultLabel.setText("❌ Delimiters not found. Use Auto-Detect or Preset buttons!");
            previewResultLabel.setForeground(Color.RED);
        }
    }

    private String extractFilename(HttpRequest request) {
        if (request == null) return "test.png";
        String body = request.bodyToString();
        int idx = body.indexOf("filename=\"");
        if (idx != -1) {
            int end = body.indexOf("\"", idx + 10);
            if (end != -1) {
                return body.substring(idx + 10, end);
            }
        }
        return "test.png";
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
                    logEntryConsumer.accept(entry);

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
