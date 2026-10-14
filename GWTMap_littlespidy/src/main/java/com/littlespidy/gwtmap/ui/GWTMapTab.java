// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.gwtmap.engine.GWTScanEngine;
import com.littlespidy.gwtmap.model.GWTDataStore;
import com.littlespidy.gwtmap.model.GWTMethod;
import com.littlespidy.gwtmap.model.GWTModuleInfo;
import com.littlespidy.gwtmap.model.GWTService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Main Suite Tab UI component for GWTMap.
 * Incorporates target acquisition, method/service triage, native editors,
 * batch probing, and deobfuscated code inspection.
 *
 * @author littlespidy
 */
public class GWTMapTab extends JPanel {

    private final MontoyaApi api;
    private final GWTDataStore dataStore;
    private final GWTScanEngine engine;

    // Top Controls
    private final JTextField urlField = new JTextField(30);
    private final JTextField baseField = new JTextField(20);
    private final JButton analyzeBtn = new JButton("Analyze Target");
    private final JButton openFileBtn = new JButton("Open Permutation Local File...");
    private final JComboBox<String> permutationCombo = new JComboBox<>();
    private final JButton headersBtn = new JButton("Headers & Cookies... (0)");
    private final JCheckBox passiveMonitorBox = new JCheckBox("Passive Monitor", true);
    private final JLabel statusLabel = new JLabel("Ready");
    private final JProgressBar progressBar = new JProgressBar();

    // Custom headers buffer
    private String customHeaders = "";

    // Sub-Tabs
    private final JTabbedPane mainTabbedPane = new JTabbedPane();

    // ── Tab 1: Methods & Payloads ───────────────────────────────────────────
    private final GWTMethodTableModel methodTableModel = new GWTMethodTableModel();
    private final JTable methodTable = new JTable(methodTableModel);
    private final JTextField searchField = new JTextField(15);
    private MultiSelectFilterButton serviceFilterBtn;
    private MultiSelectFilterButton statusFilterBtn;
    private final JCheckBox inScopeBox = new JCheckBox("In-Scope Only", false);
    private final JLabel counterLabel = new JLabel("Showing 0/0 Services | 0/0 Methods");

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private final JTextArea rawRpcArea = new JTextArea();
    private final JTextArea evidenceArea = new JTextArea();

    // ── Tab 2: Services ─────────────────────────────────────────────────────
    private final GWTServiceTableModel serviceTableModel = new GWTServiceTableModel();
    private final JTable serviceTable = new JTable(serviceTableModel);

    // ── Tab 3: Module Info ──────────────────────────────────────────────────
    private final JTextArea moduleInfoArea = new JTextArea();

    // ── Tab 4: Code Viewer ──────────────────────────────────────────────────
    private final JTextArea codeViewerArea = new JTextArea();
    private final JButton exportCodeBtn = new JButton("Save / Backup Code to Disk...");

    // ── Tab 5 & 6: Deserializer & Fuzzer ─────────────────────────────────────
    private final RpcDeserializerPanel deserializerPanel;
    private final RpcFuzzerPanel fuzzerPanel;

    // Debounce timer for search input (300ms)
    private final javax.swing.Timer filterDebounceTimer = new javax.swing.Timer(300, e -> refreshFilteredViews());
    {
        filterDebounceTimer.setRepeats(false);
    }

    public GWTMapTab(MontoyaApi api, GWTDataStore dataStore, GWTScanEngine engine) {
        this.api = api;
        this.dataStore = dataStore;
        this.engine = engine;
        this.deserializerPanel = new RpcDeserializerPanel(api);
        this.fuzzerPanel = new RpcFuzzerPanel(api);

        setLayout(new BorderLayout(4, 4));
        setBorder(new EmptyBorder(6, 6, 6, 6));

        initUI();
    }

    private void initUI() {
        // Request & Response editors from Montoya
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        add(createTopPanel(), BorderLayout.NORTH);
        add(createCenterPanel(), BorderLayout.CENTER);
        add(createBottomStatusPanel(), BorderLayout.SOUTH);
    }

    // ── Top Toolbar ──────────────────────────────────────────────────────────

    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 4));
        panel.setBorder(BorderFactory.createCompoundBorder(
                new TitledBorder("Target Acquisition & Scope"),
                new EmptyBorder(4, 6, 4, 6)
        ));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row1.add(new JLabel("Bootstrap URL:"));
        urlField.setToolTipText("Enter .nocache.js bootstrap URL");
        row1.add(urlField);

        row1.add(new JLabel("Permutation URL:"));
        baseField.setToolTipText("Enter {hash}.cache.js permutation URL or base directory override");
        row1.add(baseField);

        analyzeBtn.addActionListener(e -> startAnalysis());
        row1.add(analyzeBtn);

        openFileBtn.setToolTipText("Select offline .cache.js permutation file");
        openFileBtn.addActionListener(e -> openLocalFile());
        row1.add(openFileBtn);

        headersBtn.addActionListener(e -> showHeadersDialog());
        row1.add(headersBtn);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row2.add(new JLabel("Active Permutation:"));
        permutationCombo.setPreferredSize(new Dimension(240, 24));
        permutationCombo.addActionListener(e -> onPermutationChanged());
        row2.add(permutationCombo);

        passiveMonitorBox.setToolTipText("Automatically detect and extract GWT files passing through Burp Proxy");
        row2.add(passiveMonitorBox);

        JButton resetBtn = new JButton("Reset All");
        resetBtn.addActionListener(e -> resetAll());
        row2.add(resetBtn);

        panel.add(row1, BorderLayout.NORTH);
        panel.add(row2, BorderLayout.SOUTH);
        return panel;
    }

    // ── Center Main Tabs ─────────────────────────────────────────────────────

    private JComponent createCenterPanel() {
        mainTabbedPane.addTab("Methods & Payloads", createMethodsPanel());
        mainTabbedPane.addTab("Services & Policies", createServicesPanel());
        mainTabbedPane.addTab("Module Info", createModuleInfoPanel());
        mainTabbedPane.addTab("Deobfuscated Code", createCodeViewerPanel());
        mainTabbedPane.addTab("RPC Deserializer", deserializerPanel);
        mainTabbedPane.addTab("RPC Fuzzer & Tester", fuzzerPanel);
        return mainTabbedPane;
    }

    private JPanel createMethodsPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        // Filter Toolbar
        JPanel filterToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterToolbar.add(new JLabel("Search (-f):"));
        searchField.setToolTipText("Filter by method name, service, signature or URL");
        searchField.getDocument().addDocumentListener(new SimpleDocListener(this::triggerDebouncedFilter));
        filterToolbar.add(searchField);

        serviceFilterBtn = new MultiSelectFilterButton(
                "Service", List.of("All Services"), sel -> refreshFilteredViews()
        );
        filterToolbar.add(serviceFilterBtn);

        statusFilterBtn = new MultiSelectFilterButton(
                "Status", List.of("All Statuses", "Probed", "Unprobed", "2xx", "200", "4xx", "5xx"), sel -> refreshFilteredViews()
        );
        filterToolbar.add(statusFilterBtn);

        inScopeBox.addActionListener(e -> refreshFilteredViews());
        filterToolbar.add(inScopeBox);

        JButton resetFiltersBtn = new JButton("Clear Filters");
        resetFiltersBtn.addActionListener(e -> {
            searchField.setText("");
            serviceFilterBtn.clearSelection();
            statusFilterBtn.clearSelection();
            inScopeBox.setSelected(false);
            refreshFilteredViews();
        });
        filterToolbar.add(resetFiltersBtn);

        filterToolbar.add(new JSeparator(SwingConstants.VERTICAL));
        counterLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        filterToolbar.add(counterLabel);

        panel.add(filterToolbar, BorderLayout.NORTH);

        // Center split: Table on top, Editors on bottom
        methodTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        methodTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateSelectedMethodDetails();
            }
        });

        JScrollPane tableScroll = new JScrollPane(methodTable);
        tableScroll.setPreferredSize(new Dimension(800, 260));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(tableScroll);
        splitPane.setBottomComponent(createEditorPanel());
        splitPane.setDividerLocation(260);
        splitPane.setResizeWeight(0.45);

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createEditorPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        // Sub tabs for editors
        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Request", requestEditor.uiComponent());
        editorTabs.addTab("Response", responseEditor.uiComponent());

        rawRpcArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawRpcArea.setLineWrap(true);
        rawRpcArea.setWrapStyleWord(true);
        editorTabs.addTab("GWT-RPC Payload", new JScrollPane(rawRpcArea));

        evidenceArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        evidenceArea.setEditable(false);
        editorTabs.addTab("Evidence & Types", new JScrollPane(evidenceArea));

        panel.add(editorTabs, BorderLayout.CENTER);

        // Action Toolbar
        JPanel actionToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton probeBtn = new JButton("Send Probe");
        probeBtn.setToolTipText("Execute HTTP POST probe for the selected method (--probe)");
        probeBtn.addActionListener(e -> probeSelectedMethod());
        actionToolbar.add(probeBtn);

        JButton probeAllBtn = new JButton("Probe All Visible");
        probeAllBtn.setToolTipText("Batch probe all currently filtered methods");
        probeAllBtn.addActionListener(e -> probeAllVisibleMethods());
        actionToolbar.add(probeAllBtn);

        JButton repeaterBtn = new JButton("Send to Repeater");
        repeaterBtn.addActionListener(e -> sendSelectedToRepeater());
        actionToolbar.add(repeaterBtn);

        JButton intruderBtn = new JButton("Send to Intruder");
        intruderBtn.addActionListener(e -> sendSelectedToIntruder());
        actionToolbar.add(intruderBtn);

        JButton copyPayloadBtn = new JButton("Copy RPC Payload");
        copyPayloadBtn.addActionListener(e -> copySelectedRpcPayload());
        actionToolbar.add(copyPayloadBtn);

        JButton copyReqBtn = new JButton("Copy HTTP Request");
        copyReqBtn.addActionListener(e -> copySelectedHttpRequest());
        actionToolbar.add(copyReqBtn);

        JButton sendToDeserBtn = new JButton("Send to Deserializer");
        sendToDeserBtn.addActionListener(e -> {
            GWTMethod m = getSelectedMethod();
            if (m != null) {
                deserializerPanel.setTargetUrl(m.getFullEndpointUrl());
                loadPayloadIntoDeserializer(m.getMethodRpcCall());
            }
        });
        actionToolbar.add(sendToDeserBtn);

        JButton sendToFuzzerBtn = new JButton("Send to Fuzzer");
        sendToFuzzerBtn.addActionListener(e -> {
            GWTMethod m = getSelectedMethod();
            if (m != null) {
                loadPayloadIntoFuzzer(m.getFullEndpointUrl(), m.getMethodRpcCall());
            }
        });
        actionToolbar.add(sendToFuzzerBtn);

        panel.add(actionToolbar, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createServicesPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        serviceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        panel.add(new JScrollPane(serviceTable), BorderLayout.CENTER);

        JLabel hintLabel = new JLabel("Enumerated GWT services and serialization policy strong names (--svc mode).");
        hintLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        panel.add(hintLabel, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createModuleInfoPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        moduleInfoArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        moduleInfoArea.setEditable(false);
        panel.add(new JScrollPane(moduleInfoArea), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createCodeViewerPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        codeViewerArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        codeViewerArea.setEditable(false);
        panel.add(new JScrollPane(codeViewerArea), BorderLayout.CENTER);

        JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        exportCodeBtn.addActionListener(e -> backupCodeToDisk());
        bottomRow.add(exportCodeBtn);
        panel.add(bottomRow, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createBottomStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 4));
        panel.setBorder(new EmptyBorder(2, 6, 2, 6));

        progressBar.setStringPainted(true);
        progressBar.setVisible(false);

        panel.add(statusLabel, BorderLayout.WEST);
        panel.add(progressBar, BorderLayout.EAST);
        return panel;
    }

    // ── Actions & Workflow ───────────────────────────────────────────────────

    public void setTargetUrl(String url) {
        urlField.setText(url != null ? url.trim() : "");
    }

    public boolean isPassiveMonitorEnabled() {
        return passiveMonitorBox.isSelected();
    }

    public void startAnalysis() {
        String bootstrap = urlField.getText().trim();
        String permutation = baseField.getText().trim();

        if (bootstrap.isEmpty() && permutation.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a Bootstrap URL or Permutation URL.", "GWTMap", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String target = !bootstrap.isEmpty() ? bootstrap : permutation;
        String baseOverride = !permutation.isEmpty() ? permutation : "";

        analyzeBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        statusLabel.setText("Analyzing: " + target);

        engine.analyzeUrl(target, baseOverride,
                status -> SwingUtilities.invokeLater(() -> statusLabel.setText(status)),
                () -> SwingUtilities.invokeLater(() -> {
                    analyzeBtn.setEnabled(true);
                    progressBar.setVisible(false);
                    progressBar.setIndeterminate(false);
                    onAnalysisFinished();
                })
        );
    }

    public void openLocalFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select local GWT permutation file (*.cache.js) or bootstrap (*.nocache.js)");
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File selectedFile = chooser.getSelectedFile();
            String path = selectedFile.getAbsolutePath();
            if (path.contains(".cache.js") || path.contains(".cache.html")) {
                baseField.setText(path);
                if (urlField.getText().isBlank()) {
                    urlField.setText(path);
                }
            } else {
                urlField.setText(path);
            }

            analyzeBtn.setEnabled(false);
            progressBar.setVisible(true);
            progressBar.setIndeterminate(true);
            statusLabel.setText("Loading file: " + selectedFile.getName());

            String baseOverride = baseField.getText().trim();

            engine.analyzeFile(selectedFile, baseOverride,
                    status -> SwingUtilities.invokeLater(() -> statusLabel.setText(status)),
                    () -> SwingUtilities.invokeLater(() -> {
                        analyzeBtn.setEnabled(true);
                        progressBar.setVisible(false);
                        progressBar.setIndeterminate(false);
                        onAnalysisFinished();
                    })
            );
        }
    }

    private void onAnalysisFinished() {
        GWTModuleInfo info = dataStore.getModuleInfo();

        // Update Base field if it was empty
        if (baseField.getText().isBlank()) {
            baseField.setText(info.getBaseUrl());
        }

        // Update Permutation dropdown
        permutationCombo.removeAllItems();
        List<String> perms = info.getAllPermutations();
        if (perms.isEmpty() && !"Unknown".equals(info.getActivePermutation())) {
            permutationCombo.addItem(info.getActivePermutation());
        } else {
            for (String p : perms) {
                permutationCombo.addItem(p);
            }
        }
        if (!"Unknown".equals(info.getActivePermutation())) {
            permutationCombo.setSelectedItem(info.getActivePermutation());
        }

        // Update Service filter dropdown options
        List<String> serviceNames = new ArrayList<>();
        serviceNames.add("All Services");
        for (GWTService s : dataStore.getAllServices()) {
            if (!serviceNames.contains(s.getServicePath())) {
                serviceNames.add(s.getServicePath());
            }
        }
        // Rebuild service filter options
        int filterIdx = -1;
        Container parent = serviceFilterBtn.getParent();
        if (parent != null) {
            for (int i = 0; i < parent.getComponentCount(); i++) {
                if (parent.getComponent(i) == serviceFilterBtn) {
                    filterIdx = i;
                    break;
                }
            }
            if (filterIdx != -1) {
                parent.remove(serviceFilterBtn);
                serviceFilterBtn = new MultiSelectFilterButton("Service", serviceNames, sel -> refreshFilteredViews());
                parent.add(serviceFilterBtn, filterIdx);
                parent.revalidate();
                parent.repaint();
            }
        }

        // Update Services table
        serviceTableModel.setServices(dataStore.getAllServices());

        // Update Module Info text
        updateModuleInfoDisplay();

        // Update Code viewer
        codeViewerArea.setText(dataStore.getCleanedCode());
        codeViewerArea.setCaretPosition(0);

        // Refresh Methods table
        refreshFilteredViews();
        statusLabel.setText("Analysis complete! Discovered " + dataStore.getAllMethods().size() + " methods across " + dataStore.getAllServices().size() + " services.");
    }

    private void onPermutationChanged() {
        String selected = (String) permutationCombo.getSelectedItem();
        if (selected == null || selected.equals(dataStore.getModuleInfo().getActivePermutation())) {
            return;
        }

        // If user selects a different permutation from bootstrap
        String target = urlField.getText().trim();
        if (target.startsWith("http://") || target.startsWith("https://")) {
            String baseUrl = dataStore.getModuleInfo().getBaseUrl();
            String permUrl = baseUrl + selected + ".cache.js";
            urlField.setText(permUrl);
            startAnalysis();
        }
    }

    private void updateModuleInfoDisplay() {
        GWTModuleInfo info = dataStore.getModuleInfo();
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append("  GWT Module Information\n");
        sb.append("================================================================================\n\n");
        sb.append("Target Resource     : ").append(info.getTargetUrl()).append("\n");
        sb.append("GWT Version         : ").append(info.getGwtVersion()).append("\n");
        sb.append("Content-Type        : ").append(info.getContentType()).append("\n");
        sb.append("X-GWT-Module-Base   : ").append(info.getBaseUrl()).append("\n");
        sb.append("X-GWT-Permutation   : ").append(info.getActivePermutation()).append("\n");
        sb.append("RPC Version         : ").append(info.getRpcVersion()).append("\n");
        sb.append("RPC Flags           : ").append(info.getRpcFlags()).append("\n\n");

        sb.append("Discovered Permutations (").append(info.getAllPermutations().size()).append("):\n");
        for (String p : info.getAllPermutations()) {
            sb.append("  * ").append(p).append(p.equals(info.getActivePermutation()) ? " (ACTIVE)" : "").append("\n");
        }
        sb.append("\n");

        sb.append("Deferred JS Fragments (").append(info.getDeferredFragments().size()).append("):\n");
        if (info.getDeferredFragments().isEmpty()) {
            sb.append("  (None or non-fragmented module)\n");
        } else {
            for (String f : info.getDeferredFragments()) {
                sb.append("  + ").append(f).append("\n");
            }
        }
        sb.append("\n");

        sb.append("Discovered Services : ").append(dataStore.getAllServices().size()).append("\n");
        sb.append("Discovered Methods  : ").append(dataStore.getAllMethods().size()).append("\n");

        moduleInfoArea.setText(sb.toString());
        moduleInfoArea.setCaretPosition(0);
    }

    private void triggerDebouncedFilter() {
        filterDebounceTimer.restart();
    }

    private void refreshFilteredViews() {
        String textQuery = searchField.getText();
        Set<String> selectedServices = (serviceFilterBtn != null) ? serviceFilterBtn.getSelected() : Collections.emptySet();
        Set<String> statusFilter = (statusFilterBtn != null) ? statusFilterBtn.getSelected() : Collections.emptySet();
        String statusStr = statusFilter.isEmpty() ? "All" : String.join(",", statusFilter);

        boolean inScopeOnly = inScopeBox.isSelected();

        List<GWTMethod> filtered = dataStore.getFilteredEntries(
                textQuery,
                selectedServices,
                statusStr,
                Collections.emptySet(),
                url -> {
                    if (!inScopeOnly) return true;
                    if (url == null || url.isBlank()) return false;
                    return api.scope().isInScope(url);
                }
        );

        methodTableModel.setMethods(filtered);

        int totalMethods = dataStore.getAllMethods().size();
        int totalServices = dataStore.getAllServices().size();
        long visibleServices = filtered.stream().map(GWTMethod::getServiceCategory).distinct().count();

        counterLabel.setText("Showing " + visibleServices + "/" + totalServices + " Services | "
                + filtered.size() + "/" + totalMethods + " Methods");

        if (!filtered.isEmpty()) {
            methodTable.setRowSelectionInterval(0, 0);
            updateSelectedMethodDetails();
        } else {
            try {
                requestEditor.setRequest(null);
            } catch (Throwable ignored) {}
            try {
                responseEditor.setResponse(null);
            } catch (Throwable ignored) {}
            rawRpcArea.setText("");
            evidenceArea.setText("");
        }
    }

    private void updateSelectedMethodDetails() {
        int row = methodTable.getSelectedRow();
        if (row < 0) return;

        int modelRow = methodTable.convertRowIndexToModel(row);
        GWTMethod method = methodTableModel.getMethodAt(modelRow);
        if (method == null) return;

        // Display request in Montoya Request Editor (with markers)
        try {
            HttpRequest req = engine.buildHttpRequest(method, customHeaders, true);
            requestEditor.setRequest(req);
        } catch (Throwable ignored) {}

        // Display response if probed
        try {
            if (method.isProbed() && method.getProbeResponse() != null) {
                responseEditor.setResponse(method.getProbeResponse());
            } else {
                responseEditor.setResponse(null);
            }
        } catch (Throwable ignored) {}

        // Display raw RPC call
        rawRpcArea.setText(method.getMethodRpcCall());
        rawRpcArea.setCaretPosition(0);

        // Display Evidence & Details
        StringBuilder eb = new StringBuilder();
        eb.append("Service Interface : ").append(method.getRmtSvcIntName()).append("\n");
        eb.append("Service Category  : ").append(method.getServiceCategory()).append("\n");
        eb.append("Method Name       : ").append(method.getMethodName()).append("\n");
        eb.append("Parameter Count   : ").append(method.getParamCount()).append("\n");
        eb.append("Endpoint URL      : ").append(method.getFullEndpointUrl()).append("\n");
        eb.append("Serialization Hash: ").append(method.getService() != null ? method.getService().getStrongName() : "Unknown").append("\n");
        eb.append("Signature Types   :\n");
        for (String param : method.getMethodSignature()) {
            eb.append("  - ").append(param).append("\n");
        }
        if (!method.getComplexTypes().isEmpty()) {
            eb.append("\nComplex Types Warning:\n");
            for (String ct : method.getComplexTypes()) {
                eb.append("  ! ").append(ct).append("\n");
            }
        }
        if (method.isProbed()) {
            eb.append("\nProbe Result:\n");
            eb.append("  Status  : ").append(method.getProbeStatusCode()).append("\n");
            eb.append("  Time    : ").append(method.getProbeResponseTimeMs()).append(" ms\n");
            eb.append("  Length  : ").append(method.getProbeResponseLength()).append(" bytes\n");
            eb.append("  Notes   : ").append(method.getProbeNotes()).append("\n");
        }
        evidenceArea.setText(eb.toString());
        evidenceArea.setCaretPosition(0);
    }

    private GWTMethod getSelectedMethod() {
        int row = methodTable.getSelectedRow();
        if (row < 0) return null;
        int modelRow = methodTable.convertRowIndexToModel(row);
        return methodTableModel.getMethodAt(modelRow);
    }

    private void probeSelectedMethod() {
        GWTMethod method = getSelectedMethod();
        if (method == null) {
            JOptionPane.showMessageDialog(this, "Please select a method from the table to probe.", "GWTMap", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        statusLabel.setText("Probing: " + method.getMethodName() + " (" + method.getFullEndpointUrl() + ")...");
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);

        engine.sendProbe(method, customHeaders, m -> SwingUtilities.invokeLater(() -> {
            progressBar.setVisible(false);
            progressBar.setIndeterminate(false);
            methodTableModel.fireTableDataChanged();
            updateSelectedMethodDetails();
            statusLabel.setText("Probe finished for " + m.getMethodName() + ": HTTP " + m.getProbeStatusCode()
                    + " (" + m.getProbeResponseTimeMs() + "ms)");
        }));
    }

    private void probeAllVisibleMethods() {
        int count = methodTableModel.getRowCount();
        if (count == 0) {
            JOptionPane.showMessageDialog(this, "No visible methods to probe.", "GWTMap", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to send HTTP probes to all " + count + " visible methods?",
                "Confirm Batch Probing", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        List<GWTMethod> toProbe = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            toProbe.add(methodTableModel.getMethodAt(i));
        }

        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setMinimum(0);
        progressBar.setMaximum(toProbe.size());
        progressBar.setValue(0);
        statusLabel.setText("Probing 0/" + toProbe.size() + " methods...");

        engine.probeAll(toProbe, customHeaders,
                current -> SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(current);
                    statusLabel.setText("Probing " + current + "/" + toProbe.size() + " methods...");
                    methodTableModel.fireTableDataChanged();
                }),
                () -> SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    methodTableModel.fireTableDataChanged();
                    updateSelectedMethodDetails();
                    statusLabel.setText("Batch probing completed for " + toProbe.size() + " methods!");
                    JOptionPane.showMessageDialog(this, "Batch probing completed for " + toProbe.size() + " methods!",
                            "GWTMap Prober", JOptionPane.INFORMATION_MESSAGE);
                })
        );
    }

    private void sendSelectedToRepeater() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        HttpRequest req = engine.buildHttpRequest(method, customHeaders, false);
        String tabName = "GWT: " + method.getServiceCategory() + "." + method.getMethodName();
        api.repeater().sendToRepeater(req, tabName);
        statusLabel.setText("Sent " + method.getMethodName() + " to Repeater tab [" + tabName + "]");
    }

    private void sendSelectedToIntruder() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        HttpRequest req = engine.buildHttpRequest(method, customHeaders, true);
        api.intruder().sendToIntruder(req);
        statusLabel.setText("Sent " + method.getMethodName() + " to Intruder (with §markers§)");
    }

    private void copySelectedRpcPayload() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(method.getMethodRpcCall()), null);
        statusLabel.setText("Copied GWT-RPC payload to clipboard");
    }

    private void copySelectedHttpRequest() {
        GWTMethod method = getSelectedMethod();
        if (method == null) return;
        HttpRequest req = engine.buildHttpRequest(method, customHeaders, true);
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(req.toString()), null);
        statusLabel.setText("Copied raw HTTP request to clipboard");
    }

    private void backupCodeToDisk() {
        String code = dataStore.getCleanedCode();
        if (code == null || code.isBlank()) {
            JOptionPane.showMessageDialog(this, "No cleaned code available to export.", "GWTMap", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        String perm = dataStore.getModuleInfo().getActivePermutation();
        String defaultName = System.currentTimeMillis() + "_" + perm + ".cache.js";
        chooser.setSelectedFile(new File(defaultName));

        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                Files.writeString(file.toPath(), code, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this, "Code successfully backed up to:\n" + file.getAbsolutePath(),
                        "Backup Complete", JOptionPane.INFORMATION_MESSAGE);
                statusLabel.setText("Backed up code to: " + file.getAbsolutePath());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error saving file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void showHeadersDialog() {
        JTextArea area = new JTextArea(customHeaders, 10, 35);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(new JLabel("Enter Custom Headers or Cookies (one per line, e.g. Cookie: JSESSIONID=...):"), BorderLayout.NORTH);
        p.add(new JScrollPane(area), BorderLayout.CENTER);

        int opt = JOptionPane.showConfirmDialog(this, p, "Custom Headers & Auth Injection", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (opt == JOptionPane.OK_OPTION) {
            customHeaders = area.getText().trim();
            long lines = customHeaders.isEmpty() ? 0 : Arrays.stream(customHeaders.split("\n")).filter(s -> !s.isBlank()).count();
            headersBtn.setText("Headers & Cookies... (" + lines + ")");
            statusLabel.setText("Configured " + lines + " custom headers/cookies");
            updateSelectedMethodDetails();
        }
    }

    public void resetAll() {
        dataStore.reset();
        urlField.setText("");
        baseField.setText("");
        searchField.setText("");
        permutationCombo.removeAllItems();
        customHeaders = "";
        headersBtn.setText("Headers & Cookies... (0)");
        serviceTableModel.setServices(Collections.emptyList());
        methodTableModel.setMethods(Collections.emptyList());
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
        rawRpcArea.setText("");
        evidenceArea.setText("");
        moduleInfoArea.setText("");
        codeViewerArea.setText("");
        counterLabel.setText("Showing 0/0 Services | 0/0 Methods");
        statusLabel.setText("Reset complete. Ready.");
    }

    public void loadPayloadIntoDeserializer(String rawPayload) {
        if (rawPayload != null) {
            deserializerPanel.setPayload(rawPayload);
            mainTabbedPane.setSelectedComponent(deserializerPanel);
        }
    }

    public void loadPayloadIntoFuzzer(String url, String rawPayload) {
        if (url != null) {
            fuzzerPanel.setTargetUrl(url);
        }
        if (rawPayload != null) {
            fuzzerPanel.setBaselineBody(rawPayload);
        }
        mainTabbedPane.setSelectedComponent(fuzzerPanel);
    }

    // ── Helper DocumentListener ──────────────────────────────────────────────

    private static class SimpleDocListener implements DocumentListener {
        private final Runnable onChange;
        SimpleDocListener(Runnable onChange) { this.onChange = onChange; }
        public void insertUpdate(DocumentEvent e) { onChange.run(); }
        public void removeUpdate(DocumentEvent e) { onChange.run(); }
        public void changedUpdate(DocumentEvent e) { onChange.run(); }
    }
}
