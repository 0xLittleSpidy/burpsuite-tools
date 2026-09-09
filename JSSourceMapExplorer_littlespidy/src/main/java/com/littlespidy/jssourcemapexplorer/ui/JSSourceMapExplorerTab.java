// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.littlespidy.jssourcemapexplorer.engine.*;
import com.littlespidy.jssourcemapexplorer.model.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Top-level suite tab for the JS SourceMap Explorer extension.
 * Features script classification, source map detection, interactive tree unmapping,
 * batch on-demand probing, 4-way raw HTTP message editors, cell hover tooltips,
 * and right-click copying context menus.
 *
 * @author littlespidy
 */
public class JSSourceMapExplorerTab extends JPanel {

    private final MontoyaApi api;
    private final JsDataStore dataStore;
    private final SourceMapProber prober;

    private final JTabbedPane rootTabbedPane = new JTabbedPane();

    // Scripts Table
    private final JsFilesTableModel jsTableModel = new JsFilesTableModel();
    private final JTable jsTable = new JTable(jsTableModel);

    // Unpacked Source Tree & Code Viewer
    private final SourceTreePanel sourceTreePanel;
    private final SourceCodeViewerPanel codeViewerPanel = new SourceCodeViewerPanel();

    // Dedicated Top-Level Recon Mining Panel
    private final ReconMiningPanel reconMiningPanel;

    // Dedicated Top-Level AI Security Analyst Panel (Local LLM & Antigravity CLI)
    private final AiSecurityAnalystPanel aiSecurityPanel;

    // Raw Montoya Editors for JS and SourceMap
    private final HttpRequestEditor jsRequestEditor;
    private final HttpResponseEditor jsResponseEditor;
    private final HttpRequestEditor mapRequestEditor;
    private final HttpResponseEditor mapResponseEditor;

    // Filters & Status Strip
    private final JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-Scope Only", false);
    private final JComboBox<String> httpStatusFilter = new JComboBox<>(new String[]{
        "200 OK Only",
        "All Status Codes",
        "2xx Success (200-299)",
        "3xx Redirects (300-399)",
        "4xx Client Errors (400-499)",
        "5xx Server Errors (500-599)"
    });
    private final JTextField searchField = new JTextField(15);
    private final JLabel statsLabel = new JLabel("Total: 0 | 1st Party: 0 | .map Exposed: 0 | Unpacked: 0");

    // Status Strip & Progress Bar
    private final JLabel liveStatusLabel = new JLabel("Ready. Click 'Load Proxy History' to begin.");
    private final JProgressBar progressBar = new JProgressBar();
    private JButton loadHistoryBtn;

    // Manual Row Pinning
    private final Set<Integer> pinnedIds = new LinkedHashSet<>();

    public boolean isPinned(int id) { return pinnedIds.contains(id); }
    public void pin(int id) { pinnedIds.add(id); }
    public void unpin(int id) { pinnedIds.remove(id); }
    public void clearPins() { pinnedIds.clear(); }
    public boolean hasPins() { return !pinnedIds.isEmpty(); }

    private OriginFilter currentOriginFilter = OriginFilter.ALL;

    // UI Debounce Timer
    private final javax.swing.Timer refreshTimer;
    private volatile boolean needsRefresh = false;

    // Batch Probing Execution
    private final AtomicBoolean isBatchProbing = new AtomicBoolean(false);
    private ExecutorService probeExecutor;

    public enum OriginFilter {
        ALL,
        FIRST_PARTY_ONLY,
        THIRD_PARTY_ONLY,
        EXPOSED_MAP_ONLY
    }

    public JSSourceMapExplorerTab(MontoyaApi api, JsDataStore dataStore) {
        this.api = api;
        this.dataStore = dataStore;
        this.prober = new SourceMapProber(api);

        this.jsRequestEditor = api.userInterface().createHttpRequestEditor();
        this.jsResponseEditor = api.userInterface().createHttpResponseEditor();
        this.mapRequestEditor = api.userInterface().createHttpRequestEditor();
        this.mapResponseEditor = api.userInterface().createHttpResponseEditor();

        this.sourceTreePanel = new SourceTreePanel(codeViewerPanel::displayFile);
        this.reconMiningPanel = new ReconMiningPanel(api, dataStore);
        this.aiSecurityPanel = new AiSecurityAnalystPanel(api);

        this.codeViewerPanel.setAiReviewListener(file -> {
            if (file != null) {
                openAiAnalysisForFile(file.relativePath(), file.content());
            }
        });

        this.reconMiningPanel.setAiAnalysisOpener((name, content) -> openAiAnalysisForFile(name, content));

        setLayout(new BorderLayout());

        // Setup debounced UI refresh timer (400ms)
        this.refreshTimer = new javax.swing.Timer(400, e -> {
            if (needsRefresh) {
                needsRefresh = false;
                refreshView();
            }
        });
        this.refreshTimer.setRepeats(true);
        this.refreshTimer.start();

        dataStore.addListener(() -> {
            needsRefresh = true;
        });

        // Tab 1: Welcome & Guide
        rootTabbedPane.addTab("📖 Welcome & Guide", createWelcomePanel());

        // Tab 2: JS & SourceMap Workspace
        rootTabbedPane.addTab("🗺️ JS & SourceMap Workspace", createWorkspacePanel());

        // Tab 3: Dedicated Recon & Secret Mining Tab
        rootTabbedPane.addTab("🔍 Recon & Secret Mining", reconMiningPanel);

        // Tab 4: AI Security Analyst (Local LLM / Antigravity CLI)
        rootTabbedPane.addTab("✨ AI Security Analyst", aiSecurityPanel);

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void cleanup() {
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
        if (probeExecutor != null && !probeExecutor.isShutdown()) {
            probeExecutor.shutdownNow();
        }
    }

    public void addCandidate(burp.api.montoya.http.message.requests.HttpRequest req, burp.api.montoya.http.message.responses.HttpResponse resp) {
        if (req == null || resp == null) return;

        String url = req.url();
        String host = req.httpService() != null ? req.httpService().host() : "";
        String path = req.path() != null ? req.path() : "/";

        boolean is1st = JsClassifier.isFirstParty(api, url, host);
        String originLabel = JsClassifier.getOriginLabel(is1st);

        var detection = SourceMapDetector.detect(url, resp);

        JsFileEntry entry = new JsFileEntry(
            dataStore.nextId(),
            url,
            host,
            path,
            resp.statusCode(),
            resp.body().length(),
            is1st,
            originLabel,
            detection.status(),
            detection.sourceMapLocation(),
            req,
            resp,
            ZonedDateTime.now()
        );

        String bodyStr = resp.bodyToString();
        entry.setFramework(JsFrameworkDetector.detectFramework(url, bodyStr));

        // Run Secret, Path, Cloud URLs & Dependency discovery on raw JS file
        var jsMining = SecretAndEndpointMiner.mine(url, "JS File", bodyStr);
        entry.setJsReconFindings(jsMining.secrets(), jsMining.endpoints(), jsMining.cloudUrls(), jsMining.dependencies());

        dataStore.addEntry(entry);
    }

    private JComponent createWelcomePanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        JLabel titleLabel = new JLabel("JS SourceMap Explorer");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 22));

        JTextArea descArea = new JTextArea();
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setText(
            "JS SourceMap Explorer helps security testers analyze JavaScript assets, "
                + "automatically deduplicate script URLs, classify 1st-party vs 3rd-party origins, "
                + "detect passive and active .map exposures, inspect both JS and .map raw HTTP requests/responses, "
                + "reconstruct original unminified source code trees, and mine for hidden API endpoints and secrets."
        );

        JPanel headerPanel = new JPanel(new BorderLayout(5, 10));
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descArea, BorderLayout.CENTER);

        JPanel cardGrid = new JPanel(new GridLayout(0, 2, 20, 20));

        cardGrid.add(createCard(
            "1. URL Deduplication & Classification",
            "Automatically removes duplicate script URLs and separates target application JavaScript "
                + "from third-party trackers and CDNs (Google Analytics, Stripe, Sentry, Cloudflare, etc.)."
        ));
        cardGrid.add(createCard(
            "2. Passive vs On-Demand Active Probing",
            "Clear dedicated columns track passive findings (comments, headers, inline Base64) "
                + "and on-demand active probing results (Pass 200 OK / Fail 404) for single, selected, or all requests."
        ));
        cardGrid.add(createCard(
            "3. Source Map HTTP Message Inspection",
            "When a .map file is discovered or probed, view the raw HTTP Request and Response for both the JavaScript "
                + "script and the .map file in dedicated Pretty/Raw/Hex editors."
        ));
        cardGrid.add(createCard(
            "4. Dedicated Recon & Secret Mining Tab",
            "Automatically extracts API endpoints (/api/v1/...), tokens, JWTs, AWS keys, and developer notes "
                + "across both JS assets and unpacked Source Maps in a dedicated Suite Tab with TSV export."
        ));

        panel.add(headerPanel, BorderLayout.NORTH);
        panel.add(cardGrid, BorderLayout.CENTER);

        return new JScrollPane(panel);
    }

    private JPanel createCard(String title, String description) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(200, 200, 200), 1, true),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 15));

        JTextArea desc = new JTextArea(description);
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(desc, BorderLayout.CENTER);
        return card;
    }

    private JPanel createWorkspacePanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ── Top Toolbar ──
        JPanel topContainer = new JPanel(new BorderLayout(4, 4));
        topContainer.add(createMainToolbar(), BorderLayout.NORTH);
        topContainer.add(createFilterToolbar(), BorderLayout.CENTER);

        // ── Status Strip ──
        progressBar.setPreferredSize(new Dimension(220, 16));
        progressBar.setVisible(false);
        JPanel statusRow = new JPanel(new BorderLayout(5, 5));
        statusRow.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        statusRow.add(liveStatusLabel, BorderLayout.WEST);
        statusRow.add(progressBar, BorderLayout.EAST);
        topContainer.add(statusRow, BorderLayout.SOUTH);

        panel.add(topContainer, BorderLayout.NORTH);

        // ── Top Section: Discovered Scripts Table ──
        JPanel scriptsPanel = new JPanel(new BorderLayout(5, 5));
        scriptsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Discovered JavaScript Scripts (Deduplicated)",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 13)
        ));

        jsTable.setRowSorter(new TableRowSorter<>(jsTableModel));
        jsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        setupJsTableRendering();
        setupTableKeyboardCopy(jsTable);

        jsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = jsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = jsTable.convertRowIndexToModel(row);
                    JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
                    if (entry != null) {
                        handleScriptSelection(entry);
                    }
                }
            }
        });

        scriptsPanel.add(new JScrollPane(jsTable), BorderLayout.CENTER);

        // ── Bottom Section: Inspection Tabs (Tree Explorer & 4-Way HTTP Editors) ──
        JTabbedPane bottomTabs = new JTabbedPane();

        // Sub-Tab 1: Reconstructed Project Tree & Code Viewer
        JSplitPane treeSplit = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            sourceTreePanel,
            codeViewerPanel
        );
        treeSplit.setResizeWeight(0.30);
        bottomTabs.addTab("🌲 Reconstructed Source Tree", treeSplit);

        // Sub-Tab 2: Raw JS HTTP Messages
        JTabbedPane jsHttpTabs = new JTabbedPane();
        jsHttpTabs.addTab("📤 JS Request", jsRequestEditor.uiComponent());
        jsHttpTabs.addTab("📥 JS Response", jsResponseEditor.uiComponent());
        bottomTabs.addTab("📄 JS HTTP Message", jsHttpTabs);

        // Sub-Tab 3: Raw SourceMap (.map) HTTP Messages
        JTabbedPane mapHttpTabs = new JTabbedPane();
        mapHttpTabs.addTab("📤 SourceMap Request", mapRequestEditor.uiComponent());
        mapHttpTabs.addTab("📥 SourceMap Response", mapResponseEditor.uiComponent());
        bottomTabs.addTab("🗺️ SourceMap (.map) HTTP Message", mapHttpTabs);

        // Master Vertical Split: Scripts Table (Top) vs Project Details & Editors (Bottom)
        JSplitPane mainSplit = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            scriptsPanel,
            bottomTabs
        );
        mainSplit.setResizeWeight(0.40);
        panel.add(mainSplit, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createMainToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        loadHistoryBtn = new JButton("Load Proxy History");
        loadHistoryBtn.setToolTipText("Scrape and deduplicate all JavaScript responses from Burp Proxy history");
        loadHistoryBtn.addActionListener(e -> loadProxyHistory());

        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> {
            if (jsTable.getRowCount() > 0) {
                jsTable.setRowSelectionInterval(0, jsTable.getRowCount() - 1);
            }
        });

        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> jsTable.clearSelection());

        JButton pinSelectedBtn = new JButton("📌 Pin Selected");
        pinSelectedBtn.setToolTipText("Show only the selected rows (bypasses all other filters)");
        pinSelectedBtn.addActionListener(e -> {
            for (int viewRow : jsTable.getSelectedRows()) {
                int modelRow = jsTable.convertRowIndexToModel(viewRow);
                JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
                if (entry != null) pinnedIds.add(entry.getId());
            }
            refreshView();
        });

        JButton clearPinsBtn = new JButton("Clear Pins");
        clearPinsBtn.setToolTipText("Clear pinned rows and restore filtered view");
        clearPinsBtn.addActionListener(e -> {
            pinnedIds.clear();
            refreshView();
        });

        JButton probeSelectedBtn = new JButton("Probe Selected .map");
        probeSelectedBtn.setToolTipText("Actively probe selected rows for exposed .js.map files");
        probeSelectedBtn.addActionListener(e -> probeSelectedScripts());

        JButton probeAllBtn = new JButton("Probe All Visible .map");
        probeAllBtn.setToolTipText("Actively probe all currently visible/filtered scripts for .map files");
        probeAllBtn.addActionListener(e -> probeAllVisibleScripts());

        JButton unpackBtn = new JButton("Unpack / Unmap Selected");
        unpackBtn.setToolTipText("Download and parse the Source Map to reconstruct the project tree");
        unpackBtn.addActionListener(e -> unpackSelectedScript());

        JButton exportBtn = new JButton("Export Project Tree to Disk...");
        exportBtn.setToolTipText("Export all reconstructed source code files to a local directory for VS Code");
        exportBtn.addActionListener(e -> exportCurrentProjectToDisk());

        JButton downloadJsBtn = new JButton("Download JS File(s)...");
        downloadJsBtn.setToolTipText("Download and save the selected JavaScript file(s) to local disk");
        downloadJsBtn.addActionListener(e -> downloadSelectedJsFiles());

        JButton aiAnalyzeBtn = new JButton("🤖 Analyze with AI...");
        aiAnalyzeBtn.setToolTipText("Send selected JavaScript code to Local LLM (Ollama/LM Studio) or Antigravity CLI for security analysis");
        aiAnalyzeBtn.addActionListener(e -> analyzeSelectedWithAi());

        JButton clearBtn = new JButton("Clear Data");
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                this, "Clear all discovered JavaScript entries?", "Clear Data", JOptionPane.YES_NO_OPTION
            );
            if (confirm == JOptionPane.YES_OPTION) {
                pinnedIds.clear();
                dataStore.clear();
                sourceTreePanel.setProject(null);
                codeViewerPanel.displayFile(null);
                reconMiningPanel.refreshFromDataStore();
                refreshView();
            }
        });

        toolbar.add(loadHistoryBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(selectAllBtn);
        toolbar.add(deselectAllBtn);
        toolbar.add(pinSelectedBtn);
        toolbar.add(clearPinsBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(probeSelectedBtn);
        toolbar.add(probeAllBtn);
        toolbar.add(unpackBtn);
        toolbar.add(exportBtn);
        toolbar.add(downloadJsBtn);
        toolbar.add(aiAnalyzeBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(clearBtn);

        return toolbar;
    }

    private JPanel createFilterToolbar() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JPanel filtersPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JLabel filterLbl = new JLabel("Origin:");
        filterLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        filtersPanel.add(filterLbl);

        ButtonGroup group = new ButtonGroup();
        JRadioButton allBtn = new JRadioButton("All", true);
        JRadioButton firstPartyBtn = new JRadioButton("1st Party (App)");
        JRadioButton thirdPartyBtn = new JRadioButton("3rd Party (CDN/Trackers)");
        JRadioButton exposedMapBtn = new JRadioButton("Exposed .map Only");

        group.add(allBtn);
        group.add(firstPartyBtn);
        group.add(thirdPartyBtn);
        group.add(exposedMapBtn);

        allBtn.addActionListener(e -> { currentOriginFilter = OriginFilter.ALL; refreshView(); });
        firstPartyBtn.addActionListener(e -> { currentOriginFilter = OriginFilter.FIRST_PARTY_ONLY; refreshView(); });
        thirdPartyBtn.addActionListener(e -> { currentOriginFilter = OriginFilter.THIRD_PARTY_ONLY; refreshView(); });
        exposedMapBtn.addActionListener(e -> { currentOriginFilter = OriginFilter.EXPOSED_MAP_ONLY; refreshView(); });

        filtersPanel.add(allBtn);
        filtersPanel.add(firstPartyBtn);
        filtersPanel.add(thirdPartyBtn);
        filtersPanel.add(exposedMapBtn);

        filtersPanel.add(new JSeparator(SwingConstants.VERTICAL));

        JLabel statusLbl = new JLabel("Status:");
        statusLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        filtersPanel.add(statusLbl);
        httpStatusFilter.setSelectedIndex(0); // 200 OK Only by default
        httpStatusFilter.addActionListener(e -> refreshView());
        filtersPanel.add(httpStatusFilter);

        filtersPanel.add(new JSeparator(SwingConstants.VERTICAL));
        filtersPanel.add(inScopeOnlyCheckBox);
        inScopeOnlyCheckBox.addActionListener(e -> refreshView());

        filtersPanel.add(new JLabel(" Search: "));
        searchField.setToolTipText("Filter by URL, host, or script path");
        searchField.addActionListener(e -> refreshView());
        filtersPanel.add(searchField);

        JButton applyBtn = new JButton("Filter");
        applyBtn.addActionListener(e -> refreshView());
        filtersPanel.add(applyBtn);

        JButton resetBtn = new JButton("Reset");
        resetBtn.addActionListener(e -> {
            allBtn.setSelected(true);
            currentOriginFilter = OriginFilter.ALL;
            httpStatusFilter.setSelectedIndex(0); // 200 OK Only
            inScopeOnlyCheckBox.setSelected(false);
            searchField.setText("");
            refreshView();
        });
        filtersPanel.add(resetBtn);

        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 2));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        statsPanel.add(statsLabel);

        panel.add(filtersPanel, BorderLayout.WEST);
        panel.add(statsPanel, BorderLayout.EAST);

        return panel;
    }

    private void handleScriptSelection(JsFileEntry entry) {
        if (entry == null) {
            sourceTreePanel.setProject(null);
            codeViewerPanel.displayFile(null);
            return;
        }

        // 1. JS Editors
        if (entry.getRequest() != null) {
            jsRequestEditor.setRequest(entry.getRequest());
        }
        if (entry.getResponse() != null) {
            jsResponseEditor.setResponse(entry.getResponse());
        }

        // 2. Source Map Editors (clear if not available)
        if (entry.getSourceMapRequest() != null) {
            mapRequestEditor.setRequest(entry.getSourceMapRequest());
        } else {
            mapRequestEditor.setRequest(burp.api.montoya.http.message.requests.HttpRequest.httpRequest(""));
        }
        if (entry.getSourceMapResponse() != null) {
            mapResponseEditor.setResponse(entry.getSourceMapResponse());
        } else {
            mapResponseEditor.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(""));
        }

        // 3. Tree Explorer & Code Viewer
        if (entry.getUnpackedProject() != null && entry.getUnpackedProject().getTotalFiles() > 0) {
            sourceTreePanel.setProject(entry.getUnpackedProject());
        } else {
            sourceTreePanel.setProject(null);
            codeViewerPanel.displayFile(null);
        }
    }

    private void probeSelectedScripts() {
        int[] rows = jsTable.getSelectedRows();
        if (rows.length == 0) {
            JOptionPane.showMessageDialog(this, "Please select one or more JavaScript files to probe.", "Probe .map", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<JsFileEntry> targets = new ArrayList<>();
        for (int r : rows) {
            int modelRow = jsTable.convertRowIndexToModel(r);
            JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
            if (entry != null) {
                targets.add(entry);
            }
        }

        runBatchProbe(targets);
    }

    private void probeAllVisibleScripts() {
        List<JsFileEntry> targets = jsTableModel.getAllEntries();
        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No JavaScript files currently displayed to probe.", "Probe .map", JOptionPane.WARNING_MESSAGE);
            return;
        }

        runBatchProbe(targets);
    }

    private void runBatchProbe(List<JsFileEntry> targets) {
        if (isBatchProbing.get()) {
            JOptionPane.showMessageDialog(this, "A batch probe is already in progress.", "Probe In Progress", JOptionPane.WARNING_MESSAGE);
            return;
        }

        isBatchProbing.set(true);
        int total = targets.size();
        AtomicInteger completed = new AtomicInteger(0);
        AtomicInteger foundCount = new AtomicInteger(0);

        probeExecutor = Executors.newFixedThreadPool(8);

        Thread masterThread = new Thread(() -> {
            try {
                for (JsFileEntry entry : targets) {
                    probeExecutor.submit(() -> {
                        boolean found = prober.probe(entry);
                        if (found) {
                            foundCount.incrementAndGet();
                        }
                        int done = completed.incrementAndGet();
                        SwingUtilities.invokeLater(() -> {
                            statsLabel.setText(String.format("Probing %d/%d scripts... (%d maps found)", done, total, foundCount.get()));
                            jsTableModel.fireTableDataChanged();
                        });
                    });
                }

                probeExecutor.shutdown();
                while (!probeExecutor.isTerminated()) {
                    try { Thread.sleep(200); } catch (InterruptedException ignored) {}
                }

                SwingUtilities.invokeLater(() -> {
                    refreshView();
                    reconMiningPanel.refreshFromDataStore();
                    JOptionPane.showMessageDialog(
                        JSSourceMapExplorerTab.this,
                        "Probing complete across " + total + " scripts.\nDiscovered " + foundCount.get() + " exposed .map files!",
                        "Batch Probe Finished",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                });

            } finally {
                isBatchProbing.set(false);
            }
        }, "JsSourceMap-BatchProber");

        masterThread.setDaemon(true);
        masterThread.start();
    }

    private void unpackSelectedScript() {
        int row = jsTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a JavaScript file to unpack.", "Unpack Source Map", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int modelRow = jsTable.convertRowIndexToModel(row);
        JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
        if (entry == null) return;

        unpackScript(entry);
    }

    private void unpackScript(JsFileEntry entry) {
        String mapLocation = entry.getSourceMapLocation();
        if (mapLocation == null || mapLocation.trim().isEmpty()) {
            // Attempt to probe default .map if not yet set
            String baseUrl = entry.getUrl();
            int qIdx = baseUrl.indexOf('?');
            mapLocation = (qIdx != -1 ? baseUrl.substring(0, qIdx) : baseUrl) + ".map";
        }

        final String targetLocation = mapLocation;

        SwingWorker<UnpackedProject, Void> worker = new SwingWorker<>() {
            @Override
            protected UnpackedProject doInBackground() {
                String mapJson;
                if (entry.getPassiveMapStatus() == PassiveMapStatus.INLINE_BASE64) {
                    mapJson = targetLocation;
                } else {
                    mapJson = prober.fetchMapContent(entry, targetLocation);
                }

                if (mapJson == null || mapJson.trim().isEmpty()) {
                    return null;
                }

                return SourceMapUnpacker.unpack(targetLocation, mapJson);
            }

            @Override
            protected void done() {
                try {
                    UnpackedProject project = get();
                    if (project != null && project.getTotalFiles() > 0) {
                        entry.setUnpackedProject(project);
                        entry.setSourceMapLocation(targetLocation);
                        sourceTreePanel.setProject(project);
                        reconMiningPanel.refreshFromDataStore();
                        handleScriptSelection(entry);
                        refreshView();

                        JOptionPane.showMessageDialog(
                            JSSourceMapExplorerTab.this,
                            "Successfully unpacked " + project.getTotalFiles() + " source files (" + project.getTotalLines() + " lines)!\n"
                                + "Found " + project.getAllEndpoints().size() + " endpoints and " + project.getAllSecrets().size() + " secrets in Source Map.",
                            "Unpack Complete",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                    } else {
                        JOptionPane.showMessageDialog(
                            JSSourceMapExplorerTab.this,
                            "Failed to retrieve or parse valid Source Map JSON from: " + targetLocation,
                            "Unpack Failed",
                            JOptionPane.ERROR_MESSAGE
                        );
                    }
                } catch (Exception ex) {
                    api.logging().logToError("Error unpacking script: " + ex.getMessage());
                }
            }
        };

        worker.execute();
    }

    private void exportCurrentProjectToDisk() {
        int row = jsTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an unpacked JavaScript file first.", "Export Project", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int modelRow = jsTable.convertRowIndexToModel(row);
        JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
        if (entry == null || entry.getUnpackedProject() == null) {
            JOptionPane.showMessageDialog(this, "The selected script has not been unpacked yet. Please click 'Unpack / Unmap Selected' first.", "Export Project", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser dirChooser = new JFileChooser();
        dirChooser.setDialogTitle("Select Destination Folder to Export Source Code");
        dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int result = dirChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File destDir = dirChooser.getSelectedFile();
            var exportResult = ProjectDiskExporter.exportProject(entry.getUnpackedProject(), destDir);

            if (exportResult.success()) {
                JOptionPane.showMessageDialog(
                    this,
                    "Exported " + exportResult.filesExported() + " files to:\n" + exportResult.destinationPath() + "\n\nYou can now open this folder directly in VS Code!",
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE
                );
            } else {
                JOptionPane.showMessageDialog(
                    this,
                    "Export failed: " + exportResult.errorMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    private void downloadSelectedJsFiles() {
        int[] rows = jsTable.getSelectedRows();
        if (rows.length == 0) {
            JOptionPane.showMessageDialog(this, "Please select one or more JavaScript files to download.", "Download JS", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<JsFileEntry> selectedEntries = new ArrayList<>();
        for (int r : rows) {
            int modelRow = jsTable.convertRowIndexToModel(r);
            JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
            if (entry != null && entry.getResponse() != null) {
                selectedEntries.add(entry);
            }
        }

        if (selectedEntries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "The selected script(s) do not have a response body to download.", "Download JS", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (selectedEntries.size() == 1) {
            JsFileEntry entry = selectedEntries.get(0);
            String defaultName = extractFileNameFromUrl(entry.getUrl());
            if (!defaultName.endsWith(".js")) defaultName += ".js";

            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Save JavaScript File As");
            chooser.setSelectedFile(new File(defaultName));

            int result = chooser.showSaveDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                File target = chooser.getSelectedFile();
                try {
                    java.nio.file.Files.writeString(
                        target.toPath(),
                        entry.getResponse().bodyToString(),
                        java.nio.charset.StandardCharsets.UTF_8
                    );
                    JOptionPane.showMessageDialog(
                        this,
                        "Saved JavaScript file to:\n" + target.getAbsolutePath(),
                        "Download Complete",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(
                        this,
                        "Failed to save file: " + ex.getMessage(),
                        "Download Error",
                        JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        } else {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select Destination Folder for " + selectedEntries.size() + " JavaScript Files");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

            int result = chooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                File destDir = chooser.getSelectedFile();
                if (!destDir.exists()) destDir.mkdirs();

                int savedCount = 0;
                for (JsFileEntry entry : selectedEntries) {
                    String cleanHost = entry.getHost().replaceAll("[^a-zA-Z0-9.-]", "_");
                    String baseName = extractFileNameFromUrl(entry.getUrl());
                    if (!baseName.endsWith(".js")) baseName += ".js";
                    String uniqueName = cleanHost + "_" + entry.getId() + "_" + baseName;

                    File target = new File(destDir, uniqueName);
                    try {
                        java.nio.file.Files.writeString(
                            target.toPath(),
                            entry.getResponse().bodyToString(),
                            java.nio.charset.StandardCharsets.UTF_8
                        );
                        savedCount++;
                    } catch (Exception ex) {
                        api.logging().logToError("Error saving " + uniqueName + ": " + ex.getMessage());
                    }
                }

                JOptionPane.showMessageDialog(
                    this,
                    "Successfully downloaded " + savedCount + " JavaScript files to:\n" + destDir.getAbsolutePath(),
                    "Batch Download Complete",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        }
    }

    private static String extractFileNameFromUrl(String url) {
        if (url == null || url.isEmpty()) return "script.js";
        try {
            int qIdx = url.indexOf('?');
            String clean = (qIdx != -1) ? url.substring(0, qIdx) : url;
            int slashIdx = clean.lastIndexOf('/');
            if (slashIdx != -1 && slashIdx < clean.length() - 1) {
                String name = clean.substring(slashIdx + 1).replaceAll("[^a-zA-Z0-9._-]", "_");
                return name.isEmpty() ? "script.js" : name;
            }
        } catch (Exception ignored) {}
        return "script.js";
    }

    public void openAiAnalysisForFile(String name, String content) {
        aiSecurityPanel.setTargetFile(name, content);
        rootTabbedPane.setSelectedComponent(aiSecurityPanel);
    }

    private void analyzeSelectedWithAi() {
        int row = jsTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a JavaScript file from the table to analyze.", "AI Security Analysis", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = jsTable.convertRowIndexToModel(row);
        JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
        if (entry == null || entry.getResponse() == null) {
            JOptionPane.showMessageDialog(this, "Selected file has no response content.", "AI Security Analysis", JOptionPane.WARNING_MESSAGE);
            return;
        }
        openAiAnalysisForFile(entry.getUrl(), entry.getResponse().bodyToString());
    }

    private void loadProxyHistory() {
        if (loadHistoryBtn != null) loadHistoryBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        liveStatusLabel.setText("Stage 1: Scanning Proxy history for JavaScript assets...");

        SwingWorker<List<JsFileEntry>, String> worker = new SwingWorker<>() {
            @Override
            protected List<JsFileEntry> doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                List<JsFileEntry> stage1Entries = new ArrayList<>();
                boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

                // Stage 1: Fast Scrape & Deduplication + Framework Detection
                for (ProxyHttpRequestResponse item : history) {
                    if (isCancelled()) break;
                    if (!item.hasResponse()) continue;

                    var resp = item.response();
                    // 5MB safety ceiling to prevent OutOfMemoryError on gigantic bundles
                    if (resp.body().length() > 5 * 1024 * 1024) continue;

                    String url = item.request().url();
                    if (dataStore.isKnownUrl(url)) continue; // Instant deduplication!

                    if (inScopeOnly && !api.scope().isInScope(url)) {
                        continue;
                    }

                    String ctype = resp.headerValue("Content-Type");
                    String path = item.request().path() != null ? item.request().path() : "/";

                    boolean isJs = (ctype != null && (ctype.contains("javascript") || ctype.contains("ecmascript")))
                        || path.endsWith(".js")
                        || path.endsWith(".mjs")
                        || path.contains(".js?");

                    if (!isJs) continue;

                    String host = item.request().httpService() != null ? item.request().httpService().host() : "";
                    boolean is1st = JsClassifier.isFirstParty(api, url, host);
                    String originLabel = JsClassifier.getOriginLabel(is1st);

                    var detection = SourceMapDetector.detect(url, resp);

                    JsFileEntry entry = new JsFileEntry(
                        dataStore.nextId(),
                        url,
                        host,
                        path,
                        resp.statusCode(),
                        resp.body().length(),
                        is1st,
                        originLabel,
                        detection.status(),
                        detection.sourceMapLocation(),
                        item.request(),
                        resp,
                        ZonedDateTime.now()
                    );

                    // Framework detection
                    String bodyStr = resp.bodyToString();
                    entry.setFramework(JsFrameworkDetector.detectFramework(url, bodyStr));

                    stage1Entries.add(entry);
                }

                if (stage1Entries.isEmpty()) {
                    return stage1Entries;
                }

                // Immediately register Stage 1 entries into dataStore so UI displays them
                dataStore.addEntries(stage1Entries);
                SwingUtilities.invokeLater(() -> {
                    refreshView();
                    reconMiningPanel.refreshFromDataStore();
                });

                // Stage 2: Background Bounded Executor Pool for Deep Recon Mining
                int totalToMine = stage1Entries.size();
                publish("Stage 2: Mining secrets & endpoints across " + totalToMine + " scripts...");

                int numThreads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
                ExecutorService miningPool = Executors.newFixedThreadPool(numThreads);
                AtomicInteger processed = new AtomicInteger(0);

                try {
                    List<java.util.concurrent.Future<?>> futures = new ArrayList<>(totalToMine);
                    for (JsFileEntry entry : stage1Entries) {
                        if (isCancelled()) break;
                        futures.add(miningPool.submit(() -> {
                            if (isCancelled()) return;
                            try {
                                if (entry.getResponse() != null) {
                                    var jsMining = SecretAndEndpointMiner.mine(entry.getUrl(), "JS File", entry.getResponse().bodyToString());
                                    entry.setJsReconFindings(jsMining.secrets(), jsMining.endpoints(), jsMining.cloudUrls(), jsMining.dependencies());
                                }
                            } catch (Exception ignored) {}

                            int cur = processed.incrementAndGet();
                            if (cur % 5 == 0 || cur == totalToMine) {
                                SwingUtilities.invokeLater(() -> {
                                    progressBar.setIndeterminate(false);
                                    progressBar.setMaximum(totalToMine);
                                    progressBar.setValue(cur);
                                    liveStatusLabel.setText(String.format("Stage 2: Mining secrets & endpoints (%d / %d)...", cur, totalToMine));
                                    jsTableModel.fireTableDataChanged();
                                });
                            }
                        }));
                    }

                    for (var f : futures) {
                        if (isCancelled()) break;
                        try {
                            f.get();
                        } catch (Exception ignored) {}
                    }
                } finally {
                    miningPool.shutdownNow();
                }

                return stage1Entries;
            }

            @Override
            protected void process(List<String> chunks) {
                if (!chunks.isEmpty()) {
                    liveStatusLabel.setText(chunks.get(chunks.size() - 1));
                }
            }

            @Override
            protected void done() {
                try {
                    List<JsFileEntry> result = get();
                    refreshView();
                    reconMiningPanel.refreshFromDataStore();
                    liveStatusLabel.setText(String.format("Loaded & mined %d new JS assets from Proxy history.", result.size()));
                    JOptionPane.showMessageDialog(
                        JSSourceMapExplorerTab.this,
                        "Proxy history ingestion complete!\nImported and analyzed " + result.size() + " new JavaScript assets.",
                        "History Loaded & Mined",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    api.logging().logToError("Error loading JS proxy history: " + ex.getMessage());
                    liveStatusLabel.setText("Error loading Proxy history: " + ex.getMessage());
                } finally {
                    progressBar.setVisible(false);
                    if (loadHistoryBtn != null) loadHistoryBtn.setEnabled(true);
                }
            }
        };

        worker.execute();
    }

    public synchronized void refreshView() {
        SwingUtilities.invokeLater(() -> {
            boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();
            String query = searchField.getText().trim().toLowerCase();
            String selectedStatus = (String) httpStatusFilter.getSelectedItem();
            if (selectedStatus == null) selectedStatus = "200 OK Only";

            List<JsFileEntry> all = dataStore.getEntries();
            List<JsFileEntry> filtered = new ArrayList<>();

            int count1st = 0;
            int countExposed = 0;
            int countUnpacked = 0;

            for (JsFileEntry e : all) {
                if (e.isFirstParty()) count1st++;
                if (e.isMapExposed()) countExposed++;
                if (e.isUnpacked()) countUnpacked++;

                // Pin gate fires first: if hasPins(), only show pinned rows
                if (hasPins()) {
                    if (pinnedIds.contains(e.getId())) {
                        filtered.add(e);
                    }
                    continue;
                }

                if (inScopeOnly && !api.scope().isInScope(e.getUrl())) {
                    continue;
                }

                // Origin filtering
                if (currentOriginFilter == OriginFilter.FIRST_PARTY_ONLY && !e.isFirstParty()) continue;
                if (currentOriginFilter == OriginFilter.THIRD_PARTY_ONLY && e.isFirstParty()) continue;
                if (currentOriginFilter == OriginFilter.EXPOSED_MAP_ONLY && !e.isMapExposed()) continue;

                // HTTP Status filtering
                int code = e.getStatusCode();
                if ("200 OK Only".equals(selectedStatus)) {
                    if (code != 200) continue;
                } else if ("2xx Success (200-299)".equals(selectedStatus)) {
                    if (code < 200 || code > 299) continue;
                } else if ("3xx Redirects (300-399)".equals(selectedStatus)) {
                    if (code < 300 || code > 399) continue;
                } else if ("4xx Client Errors (400-499)".equals(selectedStatus)) {
                    if (code < 400 || code > 499) continue;
                } else if ("5xx Server Errors (500-599)".equals(selectedStatus)) {
                    if (code < 500 || code > 599) continue;
                }

                // Search query
                if (!query.isEmpty()) {
                    boolean match = e.getUrl().toLowerCase().contains(query)
                        || e.getHost().toLowerCase().contains(query)
                        || e.getPath().toLowerCase().contains(query)
                        || (e.getFramework() != null && e.getFramework().toLowerCase().contains(query))
                        || (e.getSourceMapLocation() != null && e.getSourceMapLocation().toLowerCase().contains(query));
                    if (!match) continue;
                }

                filtered.add(e);
            }

            jsTableModel.updateData(filtered);

            String modeLabel = hasPins()
                ? "Pinned: " + pinnedIds.size()
                : "Displayed: " + filtered.size();

            statsLabel.setText(String.format(
                "Total: %d | 1st Party: %d | .map Exposed: %d | Unpacked: %d | %s",
                all.size(),
                count1st,
                countExposed,
                countUnpacked,
                modeLabel
            ));
        });
    }

    private void setupJsTableRendering() {
        jsTable.getColumnModel().getColumn(0).setMaxWidth(45);  // #
        jsTable.getColumnModel().getColumn(1).setMaxWidth(130); // Origin
        jsTable.getColumnModel().getColumn(2).setPreferredWidth(100); // Framework
        jsTable.getColumnModel().getColumn(3).setMaxWidth(55);  // Status
        jsTable.getColumnModel().getColumn(4).setPreferredWidth(140); // Host
        jsTable.getColumnModel().getColumn(5).setPreferredWidth(250); // JS Path
        jsTable.getColumnModel().getColumn(6).setPreferredWidth(125); // Passive .map
        jsTable.getColumnModel().getColumn(7).setPreferredWidth(120); // On-Demand Probe
        jsTable.getColumnModel().getColumn(8).setPreferredWidth(130); // JS Recon
        jsTable.getColumnModel().getColumn(9).setPreferredWidth(130); // Map Recon
        jsTable.getColumnModel().getColumn(10).setPreferredWidth(200); // SourceMap Location
        jsTable.getColumnModel().getColumn(11).setMaxWidth(95); // Unpacked Files
        jsTable.getColumnModel().getColumn(12).setMaxWidth(80); // Size

        // Custom renderer for whole row background and hover cloud tooltip
        jsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
            ) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                int modelRow = table.convertRowIndexToModel(row);
                JsFileEntry entry = jsTableModel.getEntryAt(modelRow);

                if (entry != null) {
                    ((JComponent) c).setToolTipText(null);

                    // 2. Row background coloring
                    if (!isSelected) {
                        if (isPinned(entry.getId())) {
                            c.setBackground(new Color(255, 250, 205)); // soft yellow highlight for pinned
                        } else if (entry.isUnpacked()) {
                            c.setBackground(new Color(230, 255, 230)); // light green
                        } else if (entry.isMapExposed()) {
                            c.setBackground(new Color(255, 245, 220)); // warm amber
                        } else if (entry.isFirstParty()) {
                            c.setBackground(new Color(245, 250, 255)); // soft 1st-party blue
                        } else {
                            c.setBackground(table.getBackground());
                        }

                        // Column-specific text colors
                        if (column == 6) { // Passive .map column
                            if (entry.getPassiveMapStatus() != null && entry.getPassiveMapStatus().isFound()) {
                                c.setForeground(new Color(180, 100, 0)); // dark amber
                            } else {
                                c.setForeground(Color.GRAY);
                            }
                        } else if (column == 7) { // On-Demand Probe column
                            if (entry.getActiveProbeStatus() == ActiveProbeStatus.PASS) {
                                c.setForeground(new Color(0, 140, 0)); // dark green
                            } else if (entry.getActiveProbeStatus() == ActiveProbeStatus.FAIL) {
                                c.setForeground(new Color(180, 0, 0)); // red
                            } else if (entry.getActiveProbeStatus() == ActiveProbeStatus.PROBING) {
                                c.setForeground(Color.BLUE);
                            } else {
                                c.setForeground(Color.GRAY);
                            }
                        } else if (column == 8 || column == 9) { // Recon columns
                            c.setForeground(new Color(40, 70, 130)); // navy blue
                        } else if (column == 2 && !"-".equals(entry.getFramework())) {
                            c.setForeground(new Color(110, 40, 150)); // purple for framework
                            setFont(getFont().deriveFont(Font.BOLD));
                        } else {
                            c.setForeground(table.getForeground());
                        }
                    }
                }
                return c;
            }
        });

        setupJsTableContextMenu();
    }

    private void setupJsTableContextMenu() {
        jsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = jsTable.rowAtPoint(e.getPoint());
                    int col = jsTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!jsTable.isRowSelected(row)) {
                            jsTable.setRowSelectionInterval(row, row);
                        }

                        int modelRow = jsTable.convertRowIndexToModel(row);
                        JsFileEntry entry = jsTableModel.getEntryAt(modelRow);
                        if (entry == null) return;

                        Object cellVal = jsTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();

                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + (cellStr.length() > 30 ? cellStr.substring(0, 27) + "..." : cellStr) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copyUrlItem = new JMenuItem("Copy Full JS URL");
                        copyUrlItem.addActionListener(ev -> copyToClipboard(entry.getUrl()));
                        menu.add(copyUrlItem);

                        if (entry.getSourceMapLocation() != null && !entry.getSourceMapLocation().isEmpty()) {
                            JMenuItem copyMapUrlItem = new JMenuItem("Copy SourceMap URL / Location");
                            copyMapUrlItem.addActionListener(ev -> copyToClipboard(entry.getSourceMapLocation()));
                            menu.add(copyMapUrlItem);
                        }

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> copySelectedRowsToClipboard(jsTable));
                        menu.add(copyRowsItem);

                        menu.addSeparator();

                        JMenuItem pinItem = new JMenuItem("📌 Pin Selected Row(s)");
                        pinItem.addActionListener(ev -> {
                            for (int viewRow : jsTable.getSelectedRows()) {
                                int mRow = jsTable.convertRowIndexToModel(viewRow);
                                JsFileEntry eEntry = jsTableModel.getEntryAt(mRow);
                                if (eEntry != null) pinnedIds.add(eEntry.getId());
                            }
                            refreshView();
                        });
                        menu.add(pinItem);

                        JMenuItem clearPinsItem = new JMenuItem("Clear Pins");
                        clearPinsItem.addActionListener(ev -> {
                            pinnedIds.clear();
                            refreshView();
                        });
                        menu.add(clearPinsItem);

                        menu.addSeparator();

                        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
                        sendRepeater.addActionListener(ev -> {
                            for (int viewRow : jsTable.getSelectedRows()) {
                                int mRow = jsTable.convertRowIndexToModel(viewRow);
                                JsFileEntry eEntry = jsTableModel.getEntryAt(mRow);
                                if (eEntry != null && eEntry.getRequest() != null) {
                                    String tabName = (eEntry.getRequest().method() != null ? eEntry.getRequest().method() : "GET")
                                        + " " + eEntry.getHost() + eEntry.getPath();
                                    api.repeater().sendToRepeater(eEntry.getRequest(), tabName);
                                }
                            }
                        });
                        menu.add(sendRepeater);

                        JMenuItem sendIntruder = new JMenuItem("Send to Intruder");
                        sendIntruder.addActionListener(ev -> {
                            for (int viewRow : jsTable.getSelectedRows()) {
                                int mRow = jsTable.convertRowIndexToModel(viewRow);
                                JsFileEntry eEntry = jsTableModel.getEntryAt(mRow);
                                if (eEntry != null && eEntry.getRequest() != null) {
                                    api.intruder().sendToIntruder(eEntry.getRequest());
                                }
                            }
                        });
                        menu.add(sendIntruder);

                        JMenuItem sendOrganizer = new JMenuItem("Send to Organizer");
                        sendOrganizer.addActionListener(ev -> {
                            for (int viewRow : jsTable.getSelectedRows()) {
                                int mRow = jsTable.convertRowIndexToModel(viewRow);
                                JsFileEntry eEntry = jsTableModel.getEntryAt(mRow);
                                if (eEntry != null && eEntry.getRequest() != null && eEntry.getResponse() != null) {
                                    api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(eEntry.getRequest(), eEntry.getResponse()));
                                }
                            }
                        });
                        menu.add(sendOrganizer);

                        menu.addSeparator();

                        JMenuItem probeItem = new JMenuItem("Probe .map for Selected Script(s)");
                        probeItem.addActionListener(ev -> probeSelectedScripts());
                        menu.add(probeItem);

                        JMenuItem unpackItem = new JMenuItem("Unpack / Unmap Selected SourceMap");
                        unpackItem.addActionListener(ev -> unpackScript(entry));
                        menu.add(unpackItem);

                        JMenuItem downloadItem = new JMenuItem("Download Selected JS File(s)...");
                        downloadItem.addActionListener(ev -> downloadSelectedJsFiles());
                        menu.add(downloadItem);

                        JMenuItem aiItem = new JMenuItem("🤖 Analyze with AI...");
                        aiItem.addActionListener(ev -> analyzeSelectedWithAi());
                        menu.add(aiItem);

                        menu.show(jsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void setupTableKeyboardCopy(JTable table) {
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copy");
        table.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedRowsToClipboard(table);
            }
        });
    }

    private static void copySelectedRowsToClipboard(JTable table) {
        int[] rows = table.getSelectedRows();
        if (rows.length == 0) return;

        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < table.getColumnCount(); col++) {
            sb.append(table.getColumnName(col)).append(col == table.getColumnCount() - 1 ? "\n" : "\t");
        }
        for (int r : rows) {
            for (int col = 0; col < table.getColumnCount(); col++) {
                Object val = table.getValueAt(r, col);
                sb.append(val != null ? val.toString() : "").append(col == table.getColumnCount() - 1 ? "\n" : "\t");
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
    }

    private static void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
