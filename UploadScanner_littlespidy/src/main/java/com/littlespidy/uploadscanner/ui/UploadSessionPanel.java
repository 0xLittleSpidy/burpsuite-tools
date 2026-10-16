package com.littlespidy.uploadscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import java.util.ArrayList;
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

    // ReDownloader Configuration Controls
    private JCheckBox redownloaderEnabledCb;
    private JTextField staticUrlField;

    // Attack Vector Checkboxes across 7 Categories
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

    // Category 6: Allowed Extensions Matrix
    private JCheckBox extWikipediaCb;
    private JCheckBox extImagesCb;
    private JCheckBox extDocsCb;
    private JCheckBox extWebDataCb;
    private JCheckBox extArchivesCb;
    private JCheckBox extMediaCb;
    private JTextField customExtField;

    // Category 7: Content-Type, File Size & EXIF
    private JCheckBox contentTypeValidationCb;
    private JCheckBox mimeSpoofingCb;
    private JCheckBox fileSizeLimitsCb;
    private JSpinner maxFileSizeSpinner;
    private JCheckBox exifLeakageCb;
    private JCheckBox exifXssCb;

    private JSpinner throttleSpinner;
    private JButton testRedlBtn;
    private JButton probeExtBtn;
    private JButton probeContentTypeBtn;
    private JButton testFileSizeBtn;
    private JButton testExifBtn;
    private JButton startScanBtn;
    private JButton stopScanBtn;
    private JLabel statusLabel;
    private JLabel previewResultLabel;

    private HttpRequestEditor uploadReqEditor;
    private HttpResponseEditor uploadRespEditor;
    private HttpRequestEditor redlReqEditor;
    private HttpResponseEditor redlRespEditor;

    private final ExecutionLogPanel sessionLogPanel;
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
        this.sessionLogPanel = new ExecutionLogPanel(api);

        initUI();
    }

    private void initUI() {
        // ── 1. Downloader Configuration (Enabled Checkbox + Directory Preset) ──
        JPanel redlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        redlPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 210, 240), 1),
                "Downloader Configuration",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 11),
                new Color(0, 80, 160)));

        redownloaderEnabledCb = new JCheckBox("Enable ReDownloader", true);
        redownloaderEnabledCb.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        redownloaderEnabledCb.setToolTipText("Enable or disable automatic re-downloading of uploaded files. If disabled, ReDownloader will not run.");

        String initialPreset = deriveUploadFileDirectoryPreset(baseRequest);
        staticUrlField = new JTextField(initialPreset, 36);
        staticUrlField.setToolTipText("Target directory preset where uploaded files are stored (supports ${FILENAME}, ${FILENAME_NO_EXT}, ${ORIG_EXT}, ${RANDOMIZE})");
        staticUrlField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { syncConfigFromUI(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { syncConfigFromUI(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { syncConfigFromUI(); }
        });

        redownloaderEnabledCb.addActionListener(e -> {
            boolean enabled = redownloaderEnabledCb.isSelected();
            staticUrlField.setEnabled(enabled);
            syncConfigFromUI();
        });

        redlPanel.add(redownloaderEnabledCb);
        redlPanel.add(Box.createHorizontalStrut(8));
        JLabel dirLabel = new JLabel("Upload File Directory:");
        dirLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        redlPanel.add(dirLabel);
        redlPanel.add(staticUrlField);
        JLabel tipLabel = new JLabel("(e.g. " + initialPreset + ")");
        tipLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        tipLabel.setForeground(Color.GRAY);
        redlPanel.add(tipLabel);

        // ── 2. Attack Vectors (Compact Multi-Column Layout) ──
        JPanel attackPanel = new JPanel(new BorderLayout(4, 4));
        attackPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180), 1),
                "Attack Types & Probes",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 11)));

        // Category 1: Server RCE
        phpCb = new JCheckBox("PHP Shells", true);
        jspCb = new JCheckBox("JSP / JSPX", true);
        aspCb = new JCheckBox("ASP / ASPX", true);
        htaccessCb = new JCheckBox("Apache .htaccess", true);
        webConfigCb = new JCheckBox("IIS web.config", true);
        cgiCb = new JCheckBox("CGI Scripts", true);
        ssiEsiCb = new JCheckBox("SSI & ESI", true);

        // Category 2: Image Libraries
        imageTragickCb = new JCheckBox("ImageTragick", true);
        magickDelegatesCb = new JCheckBox("Magick Delegates", true);
        ghostscriptCb = new JCheckBox("Ghostscript", true);
        libavformatCb = new JCheckBox("LibAVFormat SSRF", true);

        // Category 3: XML & Documents
        xxeSvgCb = new JCheckBox("SVG XXE", true);
        xxeXmlCb = new JCheckBox("XML XXE", true);
        xxeOfficeCb = new JCheckBox("Office DOCX", true);
        xxeXmpCb = new JCheckBox("XMP Metadata", true);
        pdfInjectionsCb = new JCheckBox("PDF Injections", true);
        csvFormulaCb = new JCheckBox("CSV Formula", true);

        // Category 4: Client-Side & Polyglots
        xssHtmlCb = new JCheckBox("HTML XSS", true);
        xssSvgCb = new JCheckBox("SVG XSS", true);
        xssSwfCb = new JCheckBox("Flash SWF", true);
        polyglotJpegCb = new JCheckBox("JPEG Polyglot", true);
        polyglotGifCb = new JCheckBox("GIF Polyglot", true);

        // Category 5: Archives, Quirks & DoS
        zipSlipCb = new JCheckBox("Zip Slip", true);
        tarSymlinkCb = new JCheckBox("TAR Symlink", true);
        uploadQuirksCb = new JCheckBox("Upload Quirks", true);
        eicarCb = new JCheckBox("EICAR AV Test", true);
        pixelFloodCb = new JCheckBox("DoS: Pixel Flood", false);
        billionLaughsCb = new JCheckBox("DoS: Billion Laughs", false);

        // Category 6: Allowed Extensions
        extWikipediaCb = new JCheckBox("Wikipedia (912)", true);
        extWikipediaCb.setToolTipText("Probe endpoint with all 912 consolidated file extensions extracted from Wikipedia");
        extImagesCb = new JCheckBox("Images (jpg, png..)", true);
        extDocsCb = new JCheckBox("Documents (pdf, doc..)", true);
        extWebDataCb = new JCheckBox("Web/Data (json..)", true);
        extArchivesCb = new JCheckBox("Archives (zip, tar..)", true);
        extMediaCb = new JCheckBox("Media (mp4, mp3..)", true);
        customExtField = new JTextField(8);
        customExtField.setToolTipText("Custom extensions (e.g. bak, log, sql)");
        JPanel customExtPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        customExtPanel.add(new JLabel("Custom:"));
        customExtPanel.add(customExtField);

        // Category 7: Validation & EXIF
        mimeSpoofingCb = new JCheckBox("MIME Spoofing", true);
        fileSizeLimitsCb = new JCheckBox("File Size Limits", true);
        maxFileSizeSpinner = new JSpinner(new SpinnerNumberModel(20, 1, 500, 5));
        maxFileSizeSpinner.setToolTipText("Max file size to test in MB");
        ((JSpinner.DefaultEditor) maxFileSizeSpinner.getEditor()).getTextField().setColumns(3);
        JPanel maxMbPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        maxMbPanel.add(new JLabel("Max MB:"));
        maxMbPanel.add(maxFileSizeSpinner);
        exifLeakageCb = new JCheckBox("EXIF Leakage", true);
        exifXssCb = new JCheckBox("EXIF XSS", true);
        contentTypeValidationCb = new JCheckBox("SecLists CTypes", false);
        contentTypeValidationCb.setToolTipText("Run all 2,387 MIME types from SecLists web-all-content-types.txt");

        // Layout: 7 compact vertical columns
        JPanel attackGrid = new JPanel(new GridLayout(1, 7, 8, 0));
        Color hdrColor = new Color(0, 80, 160);

        attackGrid.add(createCategoryColumn("Server RCE", hdrColor, phpCb, jspCb, aspCb, htaccessCb, webConfigCb, cgiCb, ssiEsiCb));
        attackGrid.add(createCategoryColumn("Image Libs", hdrColor, imageTragickCb, magickDelegatesCb, ghostscriptCb, libavformatCb));
        attackGrid.add(createCategoryColumn("XML & Docs", hdrColor, xxeSvgCb, xxeXmlCb, xxeOfficeCb, xxeXmpCb, pdfInjectionsCb, csvFormulaCb));
        attackGrid.add(createCategoryColumn("Client-Side", hdrColor, xssHtmlCb, xssSvgCb, xssSwfCb, polyglotJpegCb, polyglotGifCb));
        attackGrid.add(createCategoryColumn("Archives/DoS", hdrColor, zipSlipCb, tarSymlinkCb, uploadQuirksCb, eicarCb, pixelFloodCb, billionLaughsCb));
        attackGrid.add(createCategoryColumn("Allowed Exts", hdrColor, extWikipediaCb, extImagesCb, extDocsCb, extWebDataCb, extArchivesCb, extMediaCb, customExtPanel));
        attackGrid.add(createCategoryColumn("Validation & EXIF", hdrColor, mimeSpoofingCb, fileSizeLimitsCb, maxMbPanel, exifLeakageCb, exifXssCb, contentTypeValidationCb));

        // Quick toolbar
        List<JCheckBox> allAttackBoxes = new ArrayList<>(List.of(
                phpCb, jspCb, aspCb, htaccessCb, webConfigCb, cgiCb, ssiEsiCb,
                imageTragickCb, magickDelegatesCb, ghostscriptCb, libavformatCb,
                xxeSvgCb, xxeXmlCb, xxeOfficeCb, xxeXmpCb, pdfInjectionsCb, csvFormulaCb,
                xssHtmlCb, xssSvgCb, xssSwfCb, polyglotJpegCb, polyglotGifCb,
                zipSlipCb, tarSymlinkCb, uploadQuirksCb, eicarCb, pixelFloodCb, billionLaughsCb,
                extWikipediaCb, extImagesCb, extDocsCb, extWebDataCb, extArchivesCb, extMediaCb,
                mimeSpoofingCb, fileSizeLimitsCb, exifLeakageCb, exifXssCb, contentTypeValidationCb
        ));

        JPanel attackToolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 2));
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        selectAllBtn.addActionListener(e -> allAttackBoxes.forEach(b -> b.setSelected(true)));
        JButton clearAllBtn = new JButton("Clear All");
        clearAllBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        clearAllBtn.addActionListener(e -> allAttackBoxes.forEach(b -> b.setSelected(false)));
        attackToolbar.add(selectAllBtn);
        attackToolbar.add(clearAllBtn);

        attackPanel.add(attackGrid, BorderLayout.CENTER);
        attackPanel.add(attackToolbar, BorderLayout.SOUTH);

        // ── 3. Live Action & Status Toolbar ──
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        testRedlBtn = new JButton("Test ReDownloader Now");
        testRedlBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        testRedlBtn.setToolTipText("Verify URL extraction and test downloading the file from the server");
        testRedlBtn.addActionListener(e -> testReDownloader());

        probeExtBtn = new JButton("Probe Extensions");
        probeExtBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        probeExtBtn.setForeground(new Color(0, 100, 180));
        probeExtBtn.setToolTipText("Probe which file extensions are accepted by the upload endpoint");
        probeExtBtn.addActionListener(e -> probeAllowedExtensions());

        probeContentTypeBtn = new JButton("Probe Content-Types");
        probeContentTypeBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        probeContentTypeBtn.setForeground(new Color(130, 40, 130));
        probeContentTypeBtn.setToolTipText("Probe endpoint with all 2,387 MIME types from SecLists wordlist");
        probeContentTypeBtn.addActionListener(e -> probeContentTypes());

        testFileSizeBtn = new JButton("Test File Sizes");
        testFileSizeBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        testFileSizeBtn.setForeground(new Color(0, 120, 140));
        testFileSizeBtn.setToolTipText("Test file size limits with stepped probes");
        testFileSizeBtn.addActionListener(e -> testFileSizes());

        testExifBtn = new JButton("Test EXIF Leakage");
        testExifBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        testExifBtn.setForeground(new Color(180, 80, 0));
        testExifBtn.setToolTipText("Upload image with GPS & PII canary and verify whether metadata is stripped");
        testExifBtn.addActionListener(e -> testExifLeakage());

        startScanBtn = new JButton("Start Scan");
        startScanBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        startScanBtn.setForeground(new Color(0, 120, 50));
        startScanBtn.addActionListener(e -> startScan());

        stopScanBtn = new JButton("Stop");
        stopScanBtn.setEnabled(false);
        stopScanBtn.addActionListener(e -> stopScan());

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        statusLabel.setForeground(Color.GRAY);

        previewResultLabel = new JLabel("");
        previewResultLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));

        actionsPanel.add(testRedlBtn);
        actionsPanel.add(probeExtBtn);
        actionsPanel.add(probeContentTypeBtn);
        actionsPanel.add(testFileSizeBtn);
        actionsPanel.add(testExifBtn);
        actionsPanel.add(startScanBtn);
        actionsPanel.add(stopScanBtn);
        actionsPanel.add(new JLabel("Delay:"));
        throttleSpinner = new JSpinner(new SpinnerNumberModel(50, 0, 5000, 50));
        actionsPanel.add(throttleSpinner);
        actionsPanel.add(Box.createHorizontalStrut(6));
        actionsPanel.add(statusLabel);
        actionsPanel.add(Box.createHorizontalStrut(6));
        actionsPanel.add(previewResultLabel);

        // ── Top Configuration Panel: Downloader Config -> Attack Types & Probes -> Actions ──
        JPanel topConfig = new JPanel();
        topConfig.setLayout(new BoxLayout(topConfig, BoxLayout.Y_AXIS));
        topConfig.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        redlPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        topConfig.add(redlPanel);
        topConfig.add(Box.createVerticalStrut(4));

        attackPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        topConfig.add(attackPanel);
        topConfig.add(Box.createVerticalStrut(4));

        actionsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        topConfig.add(actionsPanel);

        // ── 4. Lower Message Editors ──
        uploadReqEditor = api.userInterface().createHttpRequestEditor();
        uploadRespEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        redlReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        redlRespEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        uploadReqEditor.setRequest(baseRequest);
        if (baseResponse != null) {
            uploadRespEditor.setResponse(baseResponse);
        }

        JPanel reqTabPanel = new JPanel(new BorderLayout());
        JPanel markerToolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton addMarkerBtn = new JButton("§ Add Marker");
        addMarkerBtn.setToolTipText("Wrap highlighted text in §...§ to replace filename across multiple locations");
        addMarkerBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        addMarkerBtn.setForeground(new Color(0, 100, 180));

        JButton clearMarkersBtn = new JButton("§ Clear Markers");
        clearMarkersBtn.setToolTipText("Remove all § markers from the baseline request");
        clearMarkersBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));

        JLabel markerTipLabel = new JLabel("Baseline Request (Editable) — Highlight filename & click '§ Add Marker'");
        markerTipLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        markerTipLabel.setForeground(Color.DARK_GRAY);

        addMarkerBtn.addActionListener(e -> addFilenameMarker());
        clearMarkersBtn.addActionListener(e -> clearFilenameMarkers());

        markerToolbar.add(markerTipLabel);
        markerToolbar.add(addMarkerBtn);
        markerToolbar.add(clearMarkersBtn);

        reqTabPanel.add(markerToolbar, BorderLayout.NORTH);
        reqTabPanel.add(uploadReqEditor.uiComponent(), BorderLayout.CENTER);

        JTabbedPane editorsTab = new JTabbedPane();
        editorsTab.addTab("Baseline Upload Request", reqTabPanel);
        editorsTab.addTab("Baseline Upload Response", uploadRespEditor.uiComponent());
        editorsTab.addTab("ReDownload Request", redlReqEditor.uiComponent());
        editorsTab.addTab("ReDownload Response", redlRespEditor.uiComponent());

        // ── Request Tab Container: Vertical Split between Config and Editors ──
        JPanel requestTabPanel = new JPanel(new BorderLayout());
        JSplitPane requestSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(topConfig), editorsTab);
        requestSplit.setResizeWeight(0.48);
        requestTabPanel.add(requestSplit, BorderLayout.CENTER);

        // ── 5. Main Session Tabbed Pane: Request Tab & History Tab ──
        JTabbedPane sessionTabs = new JTabbedPane();
        sessionTabs.addTab("Request", requestTabPanel);
        sessionTabs.addTab("History", sessionLogPanel);

        add(sessionTabs, BorderLayout.CENTER);
    }

    public static String deriveUploadFileDirectoryPreset(HttpRequest request) {
        if (request == null || request.path() == null || request.path().isEmpty()) {
            return "/uploads/${FILENAME}";
        }
        String path = request.path();
        int qIdx = path.indexOf('?');
        if (qIdx != -1) {
            path = path.substring(0, qIdx);
        }
        int hIdx = path.indexOf('#');
        if (hIdx != -1) {
            path = path.substring(0, hIdx);
        }
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        int lastSlash = path.lastIndexOf('/');
        String dir;
        if (lastSlash > 0) {
            dir = path.substring(0, lastSlash);
        } else if (lastSlash == 0 && path.length() > 1) {
            dir = path;
        } else {
            dir = "/uploads";
        }
        return dir.endsWith("/") ? dir + "${FILENAME}" : dir + "/${FILENAME}";
    }

    private JPanel createCategoryColumn(String title, Color titleColor, Component... components) {
        JPanel col = new JPanel();
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setAlignmentY(Component.TOP_ALIGNMENT);

        JLabel lbl = new JLabel(title);
        lbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        lbl.setForeground(titleColor);
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        col.add(lbl);
        col.add(Box.createVerticalStrut(4));

        for (Component c : components) {
            if (c instanceof JCheckBox cb) {
                cb.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
                cb.setMargin(new Insets(1, 1, 1, 1));
                cb.setAlignmentX(Component.LEFT_ALIGNMENT);
            } else if (c instanceof JComponent jc) {
                jc.setAlignmentX(Component.LEFT_ALIGNMENT);
            }
            col.add(c);
            col.add(Box.createVerticalStrut(1));
        }
        return col;
    }

    private void addFilenameMarker() {
        HttpRequest req = uploadReqEditor.getRequest();
        if (req == null) return;

        Optional<Selection> selOpt = uploadReqEditor.selection();
        if (selOpt.isPresent() && !selOpt.get().contents().toString().isEmpty()) {
            Selection sel = selOpt.get();
            int start = sel.offsets().startIndexInclusive();
            int end = sel.offsets().endIndexExclusive();
            byte[] reqBytes = req.toByteArray().getBytes();
            if (start >= 0 && end <= reqBytes.length && start < end) {
                String reqStr = new String(reqBytes, StandardCharsets.ISO_8859_1);
                String before = reqStr.substring(0, start);
                String selected = reqStr.substring(start, end);
                String after = reqStr.substring(end);
                String newReqStr = before + "§" + selected + "§" + after;
                uploadReqEditor.setRequest(HttpRequest.httpRequest(req.httpService(), ByteArray.byteArray(newReqStr.getBytes(StandardCharsets.ISO_8859_1))));
                return;
            }
        }

        // If no selection, check if filename="..." exists in body and wrap it automatically!
        String body = req.bodyToString();
        int fnIdx = body.indexOf("filename=\"");
        if (fnIdx != -1) {
            int fnEnd = body.indexOf("\"", fnIdx + 10);
            if (fnEnd != -1) {
                String fn = body.substring(fnIdx + 10, fnEnd);
                if (!fn.startsWith("§") && !fn.endsWith("§")) {
                    String newBody = body.substring(0, fnIdx + 10) + "§" + fn + "§" + body.substring(fnEnd);
                    uploadReqEditor.setRequest(req.withBody(newBody));
                }
            }
        }
    }

    private void clearFilenameMarkers() {
        HttpRequest req = uploadReqEditor.getRequest();
        if (req == null) return;
        byte[] reqBytes = req.toByteArray().getBytes();
        String reqStr = new String(reqBytes, StandardCharsets.ISO_8859_1);
        String clearedStr = reqStr.replace("§", "");
        uploadReqEditor.setRequest(HttpRequest.httpRequest(req.httpService(), ByteArray.byteArray(clearedStr.getBytes(StandardCharsets.ISO_8859_1))));
    }

    private void syncConfigFromUI() {
        ReDownloaderConfig rConfig = config.getRedownloaderConfig();
        rConfig.setEnabled(redownloaderEnabledCb.isSelected());
        rConfig.setStaticUrl(staticUrlField.getText().trim());

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

        // Category 6: Allowed Extensions Matrix
        config.setTestExtWikipedia(extWikipediaCb.isSelected());
        config.setTestExtImages(extImagesCb.isSelected());
        config.setTestExtDocuments(extDocsCb.isSelected());
        config.setTestExtWebData(extWebDataCb.isSelected());
        config.setTestExtArchives(extArchivesCb.isSelected());
        config.setTestExtMedia(extMediaCb.isSelected());
        config.setTestAllowedExtensions(extWikipediaCb.isSelected() || extImagesCb.isSelected() || extDocsCb.isSelected() ||
                extWebDataCb.isSelected() || extArchivesCb.isSelected() || extMediaCb.isSelected() ||
                (customExtField != null && !customExtField.getText().trim().isEmpty()));
        if (customExtField != null) {
            config.setCustomExtensions(customExtField.getText());
        }

        // Category 7: Validation, File Size & EXIF Metadata
        if (contentTypeValidationCb != null) {
            config.setTestContentTypeValidation(contentTypeValidationCb.isSelected());
            config.setTestSecListsWordlist(contentTypeValidationCb.isSelected());
        }
        if (mimeSpoofingCb != null) {
            config.setTestMimeSpoofing(mimeSpoofingCb.isSelected());
        }
        if (fileSizeLimitsCb != null) {
            config.setTestFileSizeLimits(fileSizeLimitsCb.isSelected());
        }
        if (maxFileSizeSpinner != null) {
            config.setMaxFileSizeMb((Integer) maxFileSizeSpinner.getValue());
        }
        if (exifLeakageCb != null) {
            config.setTestExifLeakage(exifLeakageCb.isSelected());
        }
        if (exifXssCb != null) {
            config.setTestExifXss(exifXssCb.isSelected());
            config.setTestExifInjections(exifXssCb.isSelected());
        }

        config.setThrottleMs((Integer) throttleSpinner.getValue());
    }

    private void testReDownloader() {
        syncConfigFromUI();
        if (!config.getRedownloaderConfig().isEnabled()) {
            previewResultLabel.setText("ReDownloader is disabled.");
            previewResultLabel.setForeground(Color.GRAY);
            return;
        }

        HttpRequest activeReq = (uploadReqEditor != null && uploadReqEditor.getRequest() != null)
                ? uploadReqEditor.getRequest()
                : baseRequest;

        ReDownloaderEngine engine = new ReDownloaderEngine(api, config.getRedownloaderConfig());
        String responseStr = baseResponse != null ? baseResponse.bodyToString() : "";
        String testFilename = extractFilename(activeReq);
        MarkerHighlighter.ExtractionResult extraction = engine.parseDownloadUrl(responseStr, testFilename);

        if (extraction.isFound()) {
            String targetUrl = extraction.getExtractedText();
            previewResultLabel.setText("Testing GET: " + targetUrl + " ...");
            previewResultLabel.setForeground(new Color(0, 100, 180));

            if (uploadRespEditor != null && baseResponse != null) {
                uploadRespEditor.setSearchExpression(targetUrl);
            }

            HttpRequest redlReq = engine.buildRedownloadRequest(activeReq, targetUrl);
            if (redlReq != null) {
                redlReqEditor.setRequest(redlReq);
                new Thread(() -> {
                    HttpRequestResponse respPair = engine.executeRedownload(redlReq, "");
                    SwingUtilities.invokeLater(() -> {
                        if (respPair != null && respPair.hasResponse()) {
                            redlRespEditor.setResponse(respPair.response());
                            previewResultLabel.setText(String.format("HTTP %d (%d bytes) - Download Verified!",
                                    respPair.response().statusCode(), respPair.response().body().length()));
                            previewResultLabel.setForeground(new Color(0, 130, 40));
                        } else {
                            previewResultLabel.setText("Request sent but no response received.");
                            previewResultLabel.setForeground(Color.ORANGE.darker());
                        }
                    });
                }).start();
            }
        } else {
            previewResultLabel.setText("Download target could not be resolved from Directory Preset.");
            previewResultLabel.setForeground(Color.RED);
        }
    }

    private String extractFilename(HttpRequest request) {
        return UploadScanExecutor.extractFilenameFromRequest(request);
    }

    private UploadScanExecutor createExecutor(String taskName) {
        return new UploadScanExecutor(
                api,
                config,
                entry -> {
                    sessionLogPanel.addLogEntry(entry);
                    if (logEntryConsumer != null) {
                        logEntryConsumer.accept(entry);
                    }

                    if (entry.getStage() == StageType.REDOWNLOAD && entry.getRequestResponse() != null) {
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
                    setScanRunning(false);
                    statusLabel.setText("● " + taskName + " Completed");
                    statusLabel.setForeground(new Color(0, 140, 50));
                })
        );
    }

    private void setScanRunning(boolean isRunning) {
        startScanBtn.setEnabled(!isRunning);
        probeExtBtn.setEnabled(!isRunning);
        probeContentTypeBtn.setEnabled(!isRunning);
        testFileSizeBtn.setEnabled(!isRunning);
        testExifBtn.setEnabled(!isRunning);
        testRedlBtn.setEnabled(!isRunning);
        stopScanBtn.setEnabled(isRunning);
    }

    private void probeAllowedExtensions() {
        syncConfigFromUI();
        setScanRunning(true);
        HttpRequest activeReq = (uploadReqEditor != null && uploadReqEditor.getRequest() != null)
                ? uploadReqEditor.getRequest()
                : baseRequest;

        currentExecutor = createExecutor("Extension Probe");
        statusLabel.setForeground(new Color(0, 100, 200));
        currentExecutor.startAllowedExtensionsProbe(activeReq);
    }

    private void probeContentTypes() {
        syncConfigFromUI();
        setScanRunning(true);
        HttpRequest activeReq = (uploadReqEditor != null && uploadReqEditor.getRequest() != null)
                ? uploadReqEditor.getRequest()
                : baseRequest;

        currentExecutor = createExecutor("Content-Type Probe");
        statusLabel.setForeground(new Color(130, 40, 130));
        currentExecutor.startContentTypeProbe(activeReq);
    }

    private void testFileSizes() {
        syncConfigFromUI();
        setScanRunning(true);
        HttpRequest activeReq = (uploadReqEditor != null && uploadReqEditor.getRequest() != null)
                ? uploadReqEditor.getRequest()
                : baseRequest;

        currentExecutor = createExecutor("File Size Probe");
        statusLabel.setForeground(new Color(0, 120, 140));
        currentExecutor.startFileSizeProbe(activeReq);
    }

    private void testExifLeakage() {
        syncConfigFromUI();
        setScanRunning(true);
        HttpRequest activeReq = (uploadReqEditor != null && uploadReqEditor.getRequest() != null)
                ? uploadReqEditor.getRequest()
                : baseRequest;

        currentExecutor = createExecutor("EXIF Test");
        statusLabel.setForeground(new Color(180, 80, 0));
        currentExecutor.startExifProbe(activeReq);
    }

    private void startScan() {
        syncConfigFromUI();
        setScanRunning(true);
        HttpRequest activeReq = (uploadReqEditor != null && uploadReqEditor.getRequest() != null)
                ? uploadReqEditor.getRequest()
                : baseRequest;

        currentExecutor = createExecutor("Full Scan");
        statusLabel.setForeground(new Color(0, 100, 200));
        currentExecutor.startScan(activeReq);
    }

    private void stopScan() {
        if (currentExecutor != null) {
            currentExecutor.stop();
            statusLabel.setText("● Stopped");
            statusLabel.setForeground(Color.RED);
            setScanRunning(false);
        }
    }

    public ExecutionLogPanel getSessionLogPanel() {
        return sessionLogPanel;
    }

    public void cleanup() {
        if (currentExecutor != null) {
            currentExecutor.stop();
        }
    }
}
