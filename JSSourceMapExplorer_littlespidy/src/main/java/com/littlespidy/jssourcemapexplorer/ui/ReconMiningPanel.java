// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.jssourcemapexplorer.engine.DependencyVerifier;
import com.littlespidy.jssourcemapexplorer.model.*;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

/**
 * Dedicated top-level panel for exploring and exporting discovered API endpoints,
 * routes, hardcoded secrets, cloud storage buckets, and package dependencies.
 *
 * <p>Requests are listed sequentially in a top master table. Selecting a request
 * displays its raw HTTP Request/Response in Montoya editors alongside scoped
 * tabs: "Paths", "Secrets", "Cloud URLs", and "Dependencies".
 *
 * <p>Clicking any discovered row automatically switches to the HTTP Response editor
 * and highlights the occurrence.
 *
 * @author littlespidy
 */
public class ReconMiningPanel extends JPanel {

    private final MontoyaApi api;
    private final JsDataStore dataStore;
    private final DependencyVerifier dependencyVerifier;

    // ── Master Requests Table ──
    private final RequestsTableModel requestsTableModel = new RequestsTableModel();
    private final JTable requestsTable = new JTable(requestsTableModel);

    // ── Bottom Detail: Scoped Findings Tables ──
    private final EndpointsTableModel endpointsTableModel = new EndpointsTableModel();
    private final JTable endpointsTable = new JTable(endpointsTableModel);

    private final SecretsTableModel secretsTableModel = new SecretsTableModel();
    private final JTable secretsTable = new JTable(secretsTableModel);

    private final CloudUrlsTableModel cloudUrlsTableModel = new CloudUrlsTableModel();
    private final JTable cloudUrlsTable = new JTable(cloudUrlsTableModel);

    private final DependenciesTableModel dependenciesTableModel = new DependenciesTableModel();
    private final JTable dependenciesTable = new JTable(dependenciesTableModel);

    // ── Montoya HTTP Request/Response Editors ──
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTabbedPane httpEditorsTabs = new JTabbedPane();

    // ── Top Toolbar Controls ──
    private final JComboBox<String> sourceTypeFilter = new JComboBox<>(new String[]{
        "All Sources", "JS Files Only", "SourceMap Files Only"
    });
    private final JComboBox<String> httpStatusFilter = new JComboBox<>(new String[]{
        "All Status Codes",
        "200 OK Only",
        "2xx Success (200-299)",
        "3xx Redirects (300-399)",
        "4xx Client Errors (400-499)",
        "5xx Server Errors (500-599)"
    });
    private final JTextField searchField = new JTextField(16);
    private final JLabel statsLabel = new JLabel("Requests: 0 | Paths: 0 | Secrets: 0 | Cloud: 0 | Deps: 0");

    // ── Bottom Detail Filters ──
    private MultiSelectFilterButton pathMethodFilterBtn;
    private MultiSelectFilterButton pathTechniqueFilterBtn;
    private final JTextField pathSearchField = new JTextField(10);
    private final JLabel pathCountLabel = new JLabel("Paths: 0");

    private MultiSelectFilterButton secretCategoryFilterBtn;
    private MultiSelectFilterButton secretConfidenceFilterBtn;
    private final JTextField secretSearchField = new JTextField(10);
    private final JLabel secretCountLabel = new JLabel("Secrets: 0");

    private MultiSelectFilterButton cloudProviderFilterBtn;
    private final JTextField cloudSearchField = new JTextField(10);
    private final JLabel cloudCountLabel = new JLabel("Cloud: 0");

    private MultiSelectFilterButton depStatusFilterBtn;
    private final JTextField depSearchField = new JTextField(10);
    private final JLabel depCountLabel = new JLabel("Dependencies: 0");

    // ── Cached State ──
    private final List<JsFileEntry> masterEntries = new ArrayList<>();
    private JsFileEntry currentlySelectedEntry = null;
    private final List<DiscoveredEndpoint> currentEntryEndpoints = new ArrayList<>();
    private final List<DiscoveredSecret> currentEntrySecrets = new ArrayList<>();
    private final List<DiscoveredCloudUrl> currentEntryCloudUrls = new ArrayList<>();
    private final List<DiscoveredDependency> currentEntryDependencies = new ArrayList<>();

    private java.util.function.BiConsumer<String, String> aiAnalysisOpener;

    public void setAiAnalysisOpener(java.util.function.BiConsumer<String, String> opener) {
        this.aiAnalysisOpener = opener;
    }

    public ReconMiningPanel(MontoyaApi api, JsDataStore dataStore) {
        this.api = api;
        this.dataStore = dataStore;
        this.dependencyVerifier = new DependencyVerifier(api);

        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ── Top Master Toolbar ──
        JPanel topToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JLabel filterLbl = new JLabel("Source Type:");
        filterLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        topToolbar.add(filterLbl);
        topToolbar.add(sourceTypeFilter);
        sourceTypeFilter.addActionListener(e -> applyRequestFilter());

        JLabel statusLbl = new JLabel("Status:");
        statusLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        topToolbar.add(statusLbl);
        topToolbar.add(httpStatusFilter);
        httpStatusFilter.addActionListener(e -> applyRequestFilter());

        JLabel searchLbl = new JLabel("Search:");
        searchLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        topToolbar.add(searchLbl);
        searchField.setToolTipText("Search by URL, Host, or Path");
        searchField.addActionListener(e -> applyRequestFilter());
        topToolbar.add(searchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyRequestFilter());
        topToolbar.add(filterBtn);

        JButton resetBtn = new JButton("Reset");
        resetBtn.addActionListener(e -> {
            sourceTypeFilter.setSelectedIndex(0);
            httpStatusFilter.setSelectedIndex(0);
            searchField.setText("");
            if (pathMethodFilterBtn != null) pathMethodFilterBtn.clearSelection();
            if (pathTechniqueFilterBtn != null) pathTechniqueFilterBtn.clearSelection();
            if (secretCategoryFilterBtn != null) secretCategoryFilterBtn.clearSelection();
            if (secretConfidenceFilterBtn != null) secretConfidenceFilterBtn.clearSelection();
            if (cloudProviderFilterBtn != null) cloudProviderFilterBtn.clearSelection();
            if (depStatusFilterBtn != null) depStatusFilterBtn.clearSelection();
            pathSearchField.setText("");
            secretSearchField.setText("");
            cloudSearchField.setText("");
            depSearchField.setText("");
            refreshFromDataStore();
        });
        topToolbar.add(resetBtn);

        JButton refreshBtn = new JButton("Refresh Findings");
        refreshBtn.addActionListener(e -> refreshFromDataStore());
        topToolbar.add(refreshBtn);

        topToolbar.add(new JSeparator(SwingConstants.VERTICAL));
        topToolbar.add(statsLabel);

        add(topToolbar, BorderLayout.NORTH);

        // ── Top Section: Master Requests Table ──
        JPanel requestsPanel = new JPanel(new BorderLayout(5, 5));
        requestsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Discovered JavaScript Requests (Sequential)",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12)
        ));

        requestsTable.setRowSorter(new TableRowSorter<>(requestsTableModel));
        requestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setupTableRendering(requestsTable);
        setupTableKeyboardCopy(requestsTable);
        setupRequestsContextMenu();

        // Configure columns width
        requestsTable.getColumnModel().getColumn(0).setPreferredWidth(45);  // #
        requestsTable.getColumnModel().getColumn(1).setPreferredWidth(60);  // Method
        requestsTable.getColumnModel().getColumn(2).setPreferredWidth(400); // URL
        requestsTable.getColumnModel().getColumn(3).setPreferredWidth(55);  // Status
        requestsTable.getColumnModel().getColumn(4).setPreferredWidth(70);  // Origin
        requestsTable.getColumnModel().getColumn(5).setPreferredWidth(70);  // Paths
        requestsTable.getColumnModel().getColumn(6).setPreferredWidth(70);  // Secrets
        requestsTable.getColumnModel().getColumn(7).setPreferredWidth(70);  // Cloud
        requestsTable.getColumnModel().getColumn(8).setPreferredWidth(70);  // Deps

        requestsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = requestsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = requestsTable.convertRowIndexToModel(row);
                    JsFileEntry entry = requestsTableModel.getEntryAt(modelRow);
                    handleRequestSelected(entry);
                } else {
                    handleRequestSelected(null);
                }
            }
        });

        requestsPanel.add(new JScrollPane(requestsTable), BorderLayout.CENTER);

        // ── Bottom Section: Left (HTTP Request/Response) | Right (Findings Tabs) ──
        httpEditorsTabs.addTab("Request", requestEditor.uiComponent());
        httpEditorsTabs.addTab("Response", responseEditor.uiComponent());

        JTabbedPane findingsTabs = new JTabbedPane();
        findingsTabs.addTab("Paths", createPathsPanel());
        findingsTabs.addTab("Secrets", createSecretsPanel());
        findingsTabs.addTab("Cloud URLs", createCloudUrlsPanel());
        findingsTabs.addTab("Dependencies", createDependenciesPanel());

        JSplitPane detailSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, httpEditorsTabs, findingsTabs);
        detailSplit.setResizeWeight(0.48);

        // Master Vertical Split (Requests Top, Detail Bottom)
        JSplitPane masterSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestsPanel, detailSplit);
        masterSplit.setResizeWeight(0.38);

        add(masterSplit, BorderLayout.CENTER);
    }

    // ── Sub-panel: Paths ─────────────────────────────────────────────────────

    private JPanel createPathsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JLabel mthdLbl = new JLabel("Method:");
        mthdLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(mthdLbl);

        pathMethodFilterBtn = new MultiSelectFilterButton(
            "Method",
            List.of("All Methods", "GET", "POST", "PUT", "DELETE", "PATCH", "ROUTE", "URL"),
            sel -> applyPathFilter()
        );
        toolbar.add(pathMethodFilterBtn);

        JLabel techLbl = new JLabel("Technique:");
        techLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(techLbl);

        pathTechniqueFilterBtn = new MultiSelectFilterButton(
            "Technique",
            List.of("All Techniques", "HTTP Verb Call", "API Namespace", "Relative Path", "Absolute URL", "REST Endpoint", "File Extension"),
            sel -> applyPathFilter()
        );
        toolbar.add(pathTechniqueFilterBtn);

        toolbar.add(new JLabel(" Search: "));
        pathSearchField.addActionListener(e -> applyPathFilter());
        toolbar.add(pathSearchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyPathFilter());
        toolbar.add(filterBtn);

        JButton exportBtn = new JButton("Export Paths TSV");
        exportBtn.addActionListener(e -> exportTableToTsv(endpointsTable, "Paths"));
        toolbar.add(exportBtn);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(pathCountLabel);

        endpointsTable.setRowSorter(new TableRowSorter<>(endpointsTableModel));
        setupTableRendering(endpointsTable);
        setupTableKeyboardCopy(endpointsTable);
        setupEndpointsContextMenu();

        // Click-to-locate navigation
        endpointsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = endpointsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = endpointsTable.convertRowIndexToModel(row);
                    DiscoveredEndpoint ep = endpointsTableModel.getEndpointAt(modelRow);
                    if (ep != null && ep.endpoint() != null) {
                        locateInResponse(ep.endpoint());
                    }
                }
            }
        });

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(endpointsTable), BorderLayout.CENTER);
        return panel;
    }

    // ── Sub-panel: Secrets ───────────────────────────────────────────────────

    private JPanel createSecretsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JLabel catLbl = new JLabel("Category:");
        catLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(catLbl);

        List<String> secretCategories = List.of(
            "All Categories",
            "JSON Web Token (JWT)",
            "Google API Key",
            "Stripe Secret Key",
            "GitHub Token",
            "AWS Access Key ID",
            "Private Key Header",
            "Authorization Header",
            "Generic API Secret Key",
            "Firebase API Key",
            "HTTP Basic Auth",
            "Variable:",
            "Developer Flag / Comment"
        );

        secretCategoryFilterBtn = new MultiSelectFilterButton(
            "Category",
            secretCategories,
            sel -> applySecretFilter()
        );
        toolbar.add(secretCategoryFilterBtn);

        JLabel confLbl = new JLabel("Confidence:");
        confLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(confLbl);

        secretConfidenceFilterBtn = new MultiSelectFilterButton(
            "Confidence",
            List.of("All Confidences", "High [Firm]", "Low [Tentative]"),
            sel -> applySecretFilter()
        );
        toolbar.add(secretConfidenceFilterBtn);

        toolbar.add(new JLabel(" Search: "));
        secretSearchField.addActionListener(e -> applySecretFilter());
        toolbar.add(secretSearchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applySecretFilter());
        toolbar.add(filterBtn);

        JButton exportBtn = new JButton("Export Secrets TSV");
        exportBtn.addActionListener(e -> exportTableToTsv(secretsTable, "Secrets"));
        toolbar.add(exportBtn);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(secretCountLabel);

        secretsTable.setRowSorter(new TableRowSorter<>(secretsTableModel));
        setupTableRendering(secretsTable);
        setupTableKeyboardCopy(secretsTable);
        setupSecretsContextMenu();

        // Click-to-locate navigation
        secretsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = secretsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = secretsTable.convertRowIndexToModel(row);
                    DiscoveredSecret sec = secretsTableModel.getSecretAt(modelRow);
                    if (sec != null && sec.secretValue() != null) {
                        locateInResponse(sec.secretValue());
                    }
                }
            }
        });

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(secretsTable), BorderLayout.CENTER);
        return panel;
    }

    // ── Sub-panel: Cloud URLs ────────────────────────────────────────────────

    private JPanel createCloudUrlsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JLabel provLbl = new JLabel("Provider:");
        provLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(provLbl);

        cloudProviderFilterBtn = new MultiSelectFilterButton(
            "Provider",
            List.of("All Providers", "AWS", "Azure", "Google Cloud", "Firebase", "DigitalOcean", "Oracle Cloud", "Alibaba Cloud", "Rackspace", "DreamHost"),
            sel -> applyCloudFilter()
        );
        toolbar.add(cloudProviderFilterBtn);

        toolbar.add(new JLabel(" Search: "));
        cloudSearchField.addActionListener(e -> applyCloudFilter());
        toolbar.add(cloudSearchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyCloudFilter());
        toolbar.add(filterBtn);

        JButton exportBtn = new JButton("Export Cloud TSV");
        exportBtn.addActionListener(e -> exportTableToTsv(cloudUrlsTable, "Cloud URLs"));
        toolbar.add(exportBtn);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(cloudCountLabel);

        cloudUrlsTable.setRowSorter(new TableRowSorter<>(cloudUrlsTableModel));
        setupTableRendering(cloudUrlsTable);
        setupTableKeyboardCopy(cloudUrlsTable);
        setupCloudUrlsContextMenu();

        // Click-to-locate navigation
        cloudUrlsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = cloudUrlsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = cloudUrlsTable.convertRowIndexToModel(row);
                    DiscoveredCloudUrl cu = cloudUrlsTableModel.getCloudUrlAt(modelRow);
                    if (cu != null && cu.cloudUrl() != null) {
                        locateInResponse(cu.cloudUrl());
                    }
                }
            }
        });

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(cloudUrlsTable), BorderLayout.CENTER);
        return panel;
    }

    // ── Sub-panel: Dependencies ──────────────────────────────────────────────

    private JPanel createDependenciesPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        JLabel stLbl = new JLabel("Status:");
        stLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toolbar.add(stLbl);

        depStatusFilterBtn = new MultiSelectFilterButton(
            "Status",
            List.of("All Statuses", "VULNERABLE (Unclaimed)", "Registered (OK)", "Unverified"),
            sel -> applyDependencyFilter()
        );
        toolbar.add(depStatusFilterBtn);

        toolbar.add(new JLabel(" Search: "));
        depSearchField.addActionListener(e -> applyDependencyFilter());
        toolbar.add(depSearchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyDependencyFilter());
        toolbar.add(filterBtn);

        JButton verifyBtn = new JButton("⚡ Verify Unclaimed (npm)");
        verifyBtn.setToolTipText("Check package names on registry.npmjs.org for 404 Dependency Confusion");
        verifyBtn.addActionListener(e -> {
            verifyBtn.setEnabled(false);
            verifyBtn.setText("Checking npm...");
            dependencyVerifier.verifyAll(currentEntryDependencies, () -> {
                SwingUtilities.invokeLater(() -> {
                    verifyBtn.setEnabled(true);
                    verifyBtn.setText("⚡ Verify Unclaimed (npm)");
                    applyDependencyFilter();
                });
            });
        });
        toolbar.add(verifyBtn);

        JButton exportBtn = new JButton("Export TSV");
        exportBtn.addActionListener(e -> exportTableToTsv(dependenciesTable, "Dependencies"));
        toolbar.add(exportBtn);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(depCountLabel);

        dependenciesTable.setRowSorter(new TableRowSorter<>(dependenciesTableModel));
        setupTableRendering(dependenciesTable);
        setupTableKeyboardCopy(dependenciesTable);
        setupDependenciesContextMenu();

        // Click-to-locate navigation
        dependenciesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = dependenciesTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = dependenciesTable.convertRowIndexToModel(row);
                    DiscoveredDependency dep = dependenciesTableModel.getDependencyAt(modelRow);
                    if (dep != null && dep.packageName() != null) {
                        locateInResponse(dep.packageName());
                    }
                }
            }
        });

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(dependenciesTable), BorderLayout.CENTER);
        return panel;
    }

    // ── Click-to-Locate Navigation in HTTP Response ──────────────────────────

    private void locateInResponse(String searchTarget) {
        if (searchTarget == null || searchTarget.trim().isEmpty()) return;
        httpEditorsTabs.setSelectedIndex(1); // Switch to "Response" tab
        try {
            responseEditor.setSearchExpression(searchTarget.trim());
        } catch (Exception ignored) {}
    }

    // ── Data Ingestion & Master Refresh ──────────────────────────────────────

    public synchronized void refreshFromDataStore() {
        masterEntries.clear();
        if (dataStore != null) {
            masterEntries.addAll(dataStore.getEntries());
        }
        applyRequestFilter();
    }

    private synchronized void applyRequestFilter() {
        String filterSource = (String) sourceTypeFilter.getSelectedItem();
        String filterStatus = (String) httpStatusFilter.getSelectedItem();
        if (filterSource == null) filterSource = "All Sources";
        if (filterStatus == null) filterStatus = "All Status Codes";
        String query = searchField.getText().trim().toLowerCase();

        List<JsFileEntry> filtered = new ArrayList<>();
        int totalEndpoints = 0;
        int totalSecrets = 0;
        int totalCloud = 0;
        int totalDeps = 0;

        for (JsFileEntry entry : masterEntries) {
            int code = entry.getStatusCode();
            if ("200 OK Only".equals(filterStatus)) {
                if (code != 200) continue;
            } else if ("2xx Success (200-299)".equals(filterStatus)) {
                if (code < 200 || code > 299) continue;
            } else if ("3xx Redirects (300-399)".equals(filterStatus)) {
                if (code < 300 || code > 399) continue;
            } else if ("4xx Client Errors (400-499)".equals(filterStatus)) {
                if (code < 400 || code > 499) continue;
            } else if ("5xx Server Errors (500-599)".equals(filterStatus)) {
                if (code < 500 || code > 599) continue;
            }

            int epCount = entry.getJsEndpoints().size();
            int secCount = entry.getJsSecrets().size();
            int cloudCount = entry.getJsCloudUrls().size();
            int depCount = entry.getJsDependencies().size();

            if (entry.getUnpackedProject() != null) {
                epCount += entry.getUnpackedProject().getAllEndpoints().size();
                secCount += entry.getUnpackedProject().getAllSecrets().size();
                cloudCount += entry.getUnpackedProject().getAllCloudUrls().size();
                depCount += entry.getUnpackedProject().getAllDependencies().size();
            }

            if ("SourceMap Files Only".equals(filterSource)) {
                if (!entry.isMapExposed() && entry.getUnpackedProject() == null) continue;
            }

            if (!query.isEmpty()) {
                boolean match = (entry.getUrl() != null && entry.getUrl().toLowerCase().contains(query))
                    || (entry.getHost() != null && entry.getHost().toLowerCase().contains(query))
                    || (entry.getPath() != null && entry.getPath().toLowerCase().contains(query));
                if (!match) continue;
            }

            filtered.add(entry);
            totalEndpoints += epCount;
            totalSecrets += secCount;
            totalCloud += cloudCount;
            totalDeps += depCount;
        }

        requestsTableModel.updateData(filtered);
        statsLabel.setText(String.format(
            "Requests: %d / %d | Paths: %d | Secrets: %d | Cloud: %d | Deps: %d",
            filtered.size(), masterEntries.size(), totalEndpoints, totalSecrets, totalCloud, totalDeps
        ));

        // Keep selection or select first row if available
        if (!filtered.isEmpty()) {
            int selectedIdx = -1;
            if (currentlySelectedEntry != null) {
                for (int i = 0; i < filtered.size(); i++) {
                    if (filtered.get(i).getId() == currentlySelectedEntry.getId()) {
                        selectedIdx = i;
                        break;
                    }
                }
            }
            if (selectedIdx >= 0) {
                int viewIdx = requestsTable.convertRowIndexToView(selectedIdx);
                requestsTable.setRowSelectionInterval(viewIdx, viewIdx);
            } else {
                requestsTable.setRowSelectionInterval(0, 0);
            }
        } else {
            handleRequestSelected(null);
        }
    }

    private synchronized void handleRequestSelected(JsFileEntry entry) {
        currentlySelectedEntry = entry;
        currentEntryEndpoints.clear();
        currentEntrySecrets.clear();
        currentEntryCloudUrls.clear();
        currentEntryDependencies.clear();

        if (entry == null) {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
            endpointsTableModel.updateData(Collections.emptyList());
            secretsTableModel.updateData(Collections.emptyList());
            cloudUrlsTableModel.updateData(Collections.emptyList());
            dependenciesTableModel.updateData(Collections.emptyList());
            pathCountLabel.setText("Paths: 0");
            secretCountLabel.setText("Secrets: 0");
            cloudCountLabel.setText("Cloud: 0");
            depCountLabel.setText("Dependencies: 0");
            return;
        }

        // 1. Update Editors
        if (entry.getRequest() != null) {
            requestEditor.setRequest(entry.getRequest());
        } else {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
        }

        if (entry.getResponse() != null) {
            responseEditor.setResponse(entry.getResponse());
        } else {
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        }

        // 2. Collect findings for selected request
        String filterSource = (String) sourceTypeFilter.getSelectedItem();
        if (filterSource == null) filterSource = "All Sources";

        if (!"SourceMap Files Only".equals(filterSource)) {
            currentEntryEndpoints.addAll(entry.getJsEndpoints());
            currentEntrySecrets.addAll(entry.getJsSecrets());
            currentEntryCloudUrls.addAll(entry.getJsCloudUrls());
            currentEntryDependencies.addAll(entry.getJsDependencies());
        }

        if (!"JS Files Only".equals(filterSource) && entry.getUnpackedProject() != null) {
            currentEntryEndpoints.addAll(entry.getUnpackedProject().getAllEndpoints());
            currentEntrySecrets.addAll(entry.getUnpackedProject().getAllSecrets());
            currentEntryCloudUrls.addAll(entry.getUnpackedProject().getAllCloudUrls());
            currentEntryDependencies.addAll(entry.getUnpackedProject().getAllDependencies());
        }

        applyPathFilter();
        applySecretFilter();
        applyCloudFilter();
        applyDependencyFilter();
    }

    private synchronized void applyPathFilter() {
        Set<String> selectedMethods = pathMethodFilterBtn != null ? pathMethodFilterBtn.getSelected() : Collections.emptySet();
        Set<String> selectedTechs = pathTechniqueFilterBtn != null ? pathTechniqueFilterBtn.getSelected() : Collections.emptySet();
        String query = pathSearchField.getText().trim().toLowerCase();

        List<DiscoveredEndpoint> filtered = new ArrayList<>();
        for (DiscoveredEndpoint ep : currentEntryEndpoints) {
            if (!selectedMethods.isEmpty() && !selectedMethods.contains(ep.methodGuess())) {
                continue;
            }
            if (!selectedTechs.isEmpty() && !selectedTechs.contains(ep.technique())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (ep.endpoint() != null && ep.endpoint().toLowerCase().contains(query))
                    || (ep.methodGuess() != null && ep.methodGuess().toLowerCase().contains(query))
                    || (ep.technique() != null && ep.technique().toLowerCase().contains(query))
                    || (ep.sourceLocation() != null && ep.sourceLocation().toLowerCase().contains(query))
                    || (ep.contextSnippet() != null && ep.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(ep);
        }

        endpointsTableModel.updateData(filtered);
        pathCountLabel.setText(String.format("Paths: %d / %d", filtered.size(), currentEntryEndpoints.size()));
    }

    private synchronized void applySecretFilter() {
        Set<String> selectedCategories = secretCategoryFilterBtn != null ? secretCategoryFilterBtn.getSelected() : Collections.emptySet();
        Set<String> selectedConfidences = secretConfidenceFilterBtn != null ? secretConfidenceFilterBtn.getSelected() : Collections.emptySet();
        String query = secretSearchField.getText().trim().toLowerCase();

        List<DiscoveredSecret> filtered = new ArrayList<>();
        for (DiscoveredSecret sec : currentEntrySecrets) {
            if (!selectedCategories.isEmpty()) {
                boolean catMatch = false;
                for (String sel : selectedCategories) {
                    if (sel.endsWith(":") && sec.category().startsWith(sel)) {
                        catMatch = true;
                        break;
                    } else if (sec.category().equals(sel)) {
                        catMatch = true;
                        break;
                    }
                }
                if (!catMatch) continue;
            }
            if (!selectedConfidences.isEmpty() && !selectedConfidences.contains(sec.confidence())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (sec.secretValue() != null && sec.secretValue().toLowerCase().contains(query))
                    || (sec.category() != null && sec.category().toLowerCase().contains(query))
                    || (sec.confidence() != null && sec.confidence().toLowerCase().contains(query))
                    || (sec.sourceLocation() != null && sec.sourceLocation().toLowerCase().contains(query))
                    || (sec.contextSnippet() != null && sec.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(sec);
        }

        secretsTableModel.updateData(filtered);
        secretCountLabel.setText(String.format("Secrets: %d / %d", filtered.size(), currentEntrySecrets.size()));
    }

    private synchronized void applyCloudFilter() {
        Set<String> selectedProviders = cloudProviderFilterBtn != null ? cloudProviderFilterBtn.getSelected() : Collections.emptySet();
        String query = cloudSearchField.getText().trim().toLowerCase();

        List<DiscoveredCloudUrl> filtered = new ArrayList<>();
        for (DiscoveredCloudUrl cu : currentEntryCloudUrls) {
            if (!selectedProviders.isEmpty() && !selectedProviders.contains(cu.cloudProvider())) {
                continue;
            }
            if (!query.isEmpty()) {
                boolean match = (cu.cloudUrl() != null && cu.cloudUrl().toLowerCase().contains(query))
                    || (cu.cloudProvider() != null && cu.cloudProvider().toLowerCase().contains(query))
                    || (cu.sourceLocation() != null && cu.sourceLocation().toLowerCase().contains(query))
                    || (cu.contextSnippet() != null && cu.contextSnippet().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(cu);
        }

        cloudUrlsTableModel.updateData(filtered);
        cloudCountLabel.setText(String.format("Cloud: %d / %d", filtered.size(), currentEntryCloudUrls.size()));
    }

    private synchronized void applyDependencyFilter() {
        Set<String> selectedStatuses = depStatusFilterBtn != null ? depStatusFilterBtn.getSelected() : Collections.emptySet();
        String query = depSearchField.getText().trim().toLowerCase();

        List<DiscoveredDependency> filtered = new ArrayList<>();
        for (DiscoveredDependency dep : currentEntryDependencies) {
            if (!selectedStatuses.isEmpty()) {
                boolean statusMatch = false;
                for (String sel : selectedStatuses) {
                    if (sel.startsWith("VULNERABLE") && dep.status().startsWith("VULNERABLE")) {
                        statusMatch = true;
                        break;
                    } else if (dep.status().equals(sel)) {
                        statusMatch = true;
                        break;
                    }
                }
                if (!statusMatch) continue;
            }
            if (!query.isEmpty()) {
                boolean match = (dep.packageName() != null && dep.packageName().toLowerCase().contains(query))
                    || (dep.version() != null && dep.version().toLowerCase().contains(query))
                    || (dep.status() != null && dep.status().toLowerCase().contains(query))
                    || (dep.sourceLocation() != null && dep.sourceLocation().toLowerCase().contains(query));
                if (!match) continue;
            }
            filtered.add(dep);
        }

        dependenciesTableModel.updateData(filtered);
        depCountLabel.setText(String.format("Dependencies: %d / %d", filtered.size(), currentEntryDependencies.size()));
    }

    // ── Table Rendering & Keyboard Copy ──────────────────────────────────────

    private void setupTableRendering(JTable table) {
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                JTable tbl, Object value, boolean isSelected, boolean hasFocus, int row, int column
            ) {
                Component c = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, column);

                if (value != null && !value.toString().trim().isEmpty() && !value.toString().equals("-")) {
                    String valStr = value.toString();
                    ((JComponent) c).setToolTipText("<html><div style='max-width: 600px; padding: 4px; font-family: monospace; font-size: 11px; word-wrap: break-word;'>"
                        + escapeHtml(valStr) + "<br><br><i>[Click row to jump to this finding in Response]</i></div></html>");
                } else {
                    ((JComponent) c).setToolTipText(null);
                }

                if (!isSelected) {
                    String strVal = value != null ? value.toString() : "";
                    if (strVal.startsWith("VULNERABLE")) {
                        c.setBackground(new Color(255, 230, 230)); // light red highlight for vulnerable packages
                        c.setForeground(new Color(180, 0, 0));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else if ("High [Firm]".equals(strVal)) {
                        c.setBackground(new Color(255, 245, 230)); // light orange for high confidence secrets
                        c.setForeground(new Color(160, 80, 0));
                    } else if (row % 2 == 1) {
                        c.setBackground(new Color(250, 250, 252));
                        c.setForeground(tbl.getForeground());
                    } else {
                        c.setBackground(tbl.getBackground());
                        c.setForeground(tbl.getForeground());
                    }
                }
                return c;
            }
        });
    }

    private void setupTableKeyboardCopy(JTable table) {
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copy");
        table.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportTableToTsv(table, "Table Selection");
            }
        });
    }

    // ── Context Menus ────────────────────────────────────────────────────────

    private void setupRequestsContextMenu() {
        requestsTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = requestsTable.rowAtPoint(e.getPoint());
                    int col = requestsTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!requestsTable.isRowSelected(row)) requestsTable.setRowSelectionInterval(row, row);
                        int modelRow = requestsTable.convertRowIndexToModel(row);
                        JsFileEntry entry = requestsTableModel.getEntryAt(modelRow);
                        if (entry == null) return;

                        Object cellVal = requestsTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + truncate(cellStr, 30) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copyUrlItem = new JMenuItem("Copy JS URL");
                        copyUrlItem.addActionListener(ev -> copyToClipboard(entry.getUrl()));
                        menu.add(copyUrlItem);

                        JMenuItem downloadItem = new JMenuItem("Download JS File...");
                        downloadItem.addActionListener(ev -> downloadJsFile(entry));
                        menu.add(downloadItem);

                        if (aiAnalysisOpener != null) {
                            JMenuItem aiItem = new JMenuItem("🤖 Analyze with AI...");
                            aiItem.addActionListener(ev -> {
                                if (entry.getResponse() != null) {
                                    aiAnalysisOpener.accept(entry.getUrl(), entry.getResponse().bodyToString());
                                } else {
                                    JOptionPane.showMessageDialog(ReconMiningPanel.this, "No response content available for AI analysis.", "AI Analysis", JOptionPane.WARNING_MESSAGE);
                                }
                            });
                            menu.add(aiItem);
                        }

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> exportTableToTsv(requestsTable, "Requests Selection"));
                        menu.add(copyRowsItem);

                        menu.show(requestsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void downloadJsFile(JsFileEntry entry) {
        if (entry == null || entry.getResponse() == null) {
            JOptionPane.showMessageDialog(this, "No response content available to download.", "Download JS", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String defaultName = extractFileName(entry.getUrl());
        if (!defaultName.endsWith(".js")) defaultName += ".js";

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save JavaScript File As");
        chooser.setSelectedFile(new java.io.File(defaultName));

        int result = chooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            java.io.File target = chooser.getSelectedFile();
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
    }

    private static String extractFileName(String url) {
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

    private void setupEndpointsContextMenu() {
        endpointsTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = endpointsTable.rowAtPoint(e.getPoint());
                    int col = endpointsTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!endpointsTable.isRowSelected(row)) endpointsTable.setRowSelectionInterval(row, row);
                        int modelRow = endpointsTable.convertRowIndexToModel(row);
                        DiscoveredEndpoint ep = endpointsTableModel.getEndpointAt(modelRow);
                        if (ep == null) return;

                        Object cellVal = endpointsTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + truncate(cellStr, 30) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copyEndpointItem = new JMenuItem("Copy Endpoint / Route");
                        copyEndpointItem.addActionListener(ev -> copyToClipboard(ep.endpoint()));
                        menu.add(copyEndpointItem);

                        JMenuItem locateItem = new JMenuItem("Jump to in Response");
                        locateItem.addActionListener(ev -> locateInResponse(ep.endpoint()));
                        menu.add(locateItem);

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> exportTableToTsv(endpointsTable, "Endpoints Selection"));
                        menu.add(copyRowsItem);

                        menu.show(endpointsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void setupSecretsContextMenu() {
        secretsTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = secretsTable.rowAtPoint(e.getPoint());
                    int col = secretsTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!secretsTable.isRowSelected(row)) secretsTable.setRowSelectionInterval(row, row);
                        int modelRow = secretsTable.convertRowIndexToModel(row);
                        DiscoveredSecret sec = secretsTableModel.getSecretAt(modelRow);
                        if (sec == null) return;

                        Object cellVal = secretsTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + truncate(cellStr, 30) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copySecretItem = new JMenuItem("Copy Secret Value");
                        copySecretItem.addActionListener(ev -> copyToClipboard(sec.secretValue()));
                        menu.add(copySecretItem);

                        JMenuItem locateItem = new JMenuItem("Jump to in Response");
                        locateItem.addActionListener(ev -> locateInResponse(sec.secretValue()));
                        menu.add(locateItem);

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> exportTableToTsv(secretsTable, "Secrets Selection"));
                        menu.add(copyRowsItem);

                        menu.show(secretsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void setupCloudUrlsContextMenu() {
        cloudUrlsTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = cloudUrlsTable.rowAtPoint(e.getPoint());
                    int col = cloudUrlsTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!cloudUrlsTable.isRowSelected(row)) cloudUrlsTable.setRowSelectionInterval(row, row);
                        int modelRow = cloudUrlsTable.convertRowIndexToModel(row);
                        DiscoveredCloudUrl cu = cloudUrlsTableModel.getCloudUrlAt(modelRow);
                        if (cu == null) return;

                        Object cellVal = cloudUrlsTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + truncate(cellStr, 30) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copyUrlItem = new JMenuItem("Copy Cloud URL");
                        copyUrlItem.addActionListener(ev -> copyToClipboard(cu.cloudUrl()));
                        menu.add(copyUrlItem);

                        JMenuItem locateItem = new JMenuItem("Jump to in Response");
                        locateItem.addActionListener(ev -> locateInResponse(cu.cloudUrl()));
                        menu.add(locateItem);

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> exportTableToTsv(cloudUrlsTable, "Cloud Selection"));
                        menu.add(copyRowsItem);

                        menu.show(cloudUrlsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void setupDependenciesContextMenu() {
        dependenciesTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = dependenciesTable.rowAtPoint(e.getPoint());
                    int col = dependenciesTable.columnAtPoint(e.getPoint());
                    if (row >= 0) {
                        if (!dependenciesTable.isRowSelected(row)) dependenciesTable.setRowSelectionInterval(row, row);
                        int modelRow = dependenciesTable.convertRowIndexToModel(row);
                        DiscoveredDependency dep = dependenciesTableModel.getDependencyAt(modelRow);
                        if (dep == null) return;

                        Object cellVal = dependenciesTable.getValueAt(row, col);
                        String cellStr = cellVal != null ? cellVal.toString() : "";

                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem copyCellItem = new JMenuItem("Copy Cell Value (\"" + truncate(cellStr, 30) + "\")");
                        copyCellItem.addActionListener(ev -> copyToClipboard(cellStr));
                        menu.add(copyCellItem);

                        JMenuItem copyPkgItem = new JMenuItem("Copy Package Name");
                        copyPkgItem.addActionListener(ev -> copyToClipboard(dep.packageName()));
                        menu.add(copyPkgItem);

                        JMenuItem verifyItem = new JMenuItem("⚡ Check on npm");
                        verifyItem.addActionListener(ev -> {
                            dependencyVerifier.verifySingle(dep);
                            applyDependencyFilter();
                        });
                        menu.add(verifyItem);

                        JMenuItem locateItem = new JMenuItem("Jump to in Response");
                        locateItem.addActionListener(ev -> locateInResponse(dep.packageName()));
                        menu.add(locateItem);

                        JMenuItem copyRowsItem = new JMenuItem("Copy Selected Row(s) as TSV");
                        copyRowsItem.addActionListener(ev -> exportTableToTsv(dependenciesTable, "Dependencies Selection"));
                        menu.add(copyRowsItem);

                        menu.show(dependenciesTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void exportTableToTsv(JTable table, String name) {
        int[] rows = table.getSelectedRows();
        boolean useAll = rows.length == 0;
        int rowCount = useAll ? table.getRowCount() : rows.length;

        if (rowCount == 0) {
            JOptionPane.showMessageDialog(this, "No data to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < table.getColumnCount(); col++) {
            sb.append(table.getColumnName(col)).append(col == table.getColumnCount() - 1 ? "\n" : "\t");
        }

        for (int r = 0; r < (useAll ? table.getRowCount() : rows.length); r++) {
            int modelRow = useAll ? r : rows[r];
            for (int col = 0; col < table.getColumnCount(); col++) {
                Object val = table.getValueAt(modelRow, col);
                sb.append(val != null ? val.toString() : "").append(col == table.getColumnCount() - 1 ? "\n" : "\t");
            }
        }

        copyToClipboard(sb.toString());
        JOptionPane.showMessageDialog(this, "Copied " + rowCount + " rows to clipboard as TSV!", "Export Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private static void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 3) + "..." : s;
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }

    // ── Table Models ─────────────────────────────────────────────────────────

    private static class RequestsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "#", "Method", "URL", "Status", "Origin", "Paths", "Secrets", "Cloud URLs", "Dependencies"
        };
        private final List<JsFileEntry> list = new ArrayList<>();

        public synchronized void updateData(List<JsFileEntry> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized JsFileEntry getEntryAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return switch (c) {
                case 0, 3, 5, 6, 7, 8 -> Integer.class;
                default -> String.class;
            };
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            JsFileEntry item = list.get(r);
            return switch (c) {
                case 0 -> item.getId();
                case 1 -> item.getRequest() != null ? item.getRequest().method() : "GET";
                case 2 -> item.getUrl();
                case 3 -> item.getStatusCode();
                case 4 -> item.getOriginLabel();
                case 5 -> {
                    int count = item.getJsEndpoints().size();
                    if (item.getUnpackedProject() != null) count += item.getUnpackedProject().getAllEndpoints().size();
                    yield count;
                }
                case 6 -> {
                    int count = item.getJsSecrets().size();
                    if (item.getUnpackedProject() != null) count += item.getUnpackedProject().getAllSecrets().size();
                    yield count;
                }
                case 7 -> {
                    int count = item.getJsCloudUrls().size();
                    if (item.getUnpackedProject() != null) count += item.getUnpackedProject().getAllCloudUrls().size();
                    yield count;
                }
                case 8 -> {
                    int count = item.getJsDependencies().size();
                    if (item.getUnpackedProject() != null) count += item.getUnpackedProject().getAllDependencies().size();
                    yield count;
                }
                default -> null;
            };
        }
    }

    private static class EndpointsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "Method", "Endpoint / Route", "Technique", "Source Type", "Location / File", "Line", "Context Snippet"
        };
        private final List<DiscoveredEndpoint> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredEndpoint> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredEndpoint getEndpointAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 5 ? Integer.class : String.class; }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredEndpoint item = list.get(r);
            return switch (c) {
                case 0 -> item.methodGuess();
                case 1 -> item.endpoint();
                case 2 -> item.technique();
                case 3 -> item.sourceType();
                case 4 -> item.sourceLocation();
                case 5 -> item.line();
                case 6 -> item.contextSnippet();
                default -> null;
            };
        }
    }

    private static class SecretsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "Category", "Secret Value / Match", "Entropy", "Confidence", "Technique", "Source Type", "Location / File", "Line", "Context Snippet"
        };
        private final List<DiscoveredSecret> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredSecret> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredSecret getSecretAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return switch (c) {
                case 2 -> Double.class;
                case 7 -> Integer.class;
                default -> String.class;
            };
        }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredSecret item = list.get(r);
            return switch (c) {
                case 0 -> item.category();
                case 1 -> item.secretValue();
                case 2 -> item.entropy();
                case 3 -> item.confidence();
                case 4 -> item.technique();
                case 5 -> item.sourceType();
                case 6 -> item.sourceLocation();
                case 7 -> item.line();
                case 8 -> item.contextSnippet();
                default -> null;
            };
        }
    }

    private static class CloudUrlsTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "Provider", "Cloud URL / Resource", "Source Type", "Location / File", "Line", "Context Snippet"
        };
        private final List<DiscoveredCloudUrl> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredCloudUrl> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredCloudUrl getCloudUrlAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 4 ? Integer.class : String.class; }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredCloudUrl item = list.get(r);
            return switch (c) {
                case 0 -> item.cloudProvider();
                case 1 -> item.cloudUrl();
                case 2 -> item.sourceType();
                case 3 -> item.sourceLocation();
                case 4 -> item.line();
                case 5 -> item.contextSnippet();
                default -> null;
            };
        }
    }

    private static class DependenciesTableModel extends AbstractTableModel {
        private static final String[] COLS = {
            "Package Name", "Version", "Type", "Status", "Verification Detail", "Source Type", "Location / File", "Line", "Context Snippet"
        };
        private final List<DiscoveredDependency> list = new ArrayList<>();

        public synchronized void updateData(List<DiscoveredDependency> data) {
            list.clear();
            if (data != null) list.addAll(data);
            fireTableDataChanged();
        }

        public synchronized DiscoveredDependency getDependencyAt(int row) {
            if (row >= 0 && row < list.size()) return list.get(row);
            return null;
        }

        @Override public int getRowCount() { return list.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 7 ? Integer.class : String.class; }

        @Override
        public synchronized Object getValueAt(int r, int c) {
            if (r < 0 || r >= list.size()) return null;
            DiscoveredDependency item = list.get(r);
            return switch (c) {
                case 0 -> item.packageName();
                case 1 -> item.version();
                case 2 -> item.dependencyType();
                case 3 -> item.status();
                case 4 -> item.verificationDetail();
                case 5 -> item.sourceType();
                case 6 -> item.sourceLocation();
                case 7 -> item.line();
                case 8 -> item.contextSnippet();
                default -> null;
            };
        }
    }
}
