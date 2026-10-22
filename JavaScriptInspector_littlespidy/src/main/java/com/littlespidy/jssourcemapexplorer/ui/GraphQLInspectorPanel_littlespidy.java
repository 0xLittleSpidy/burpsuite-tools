// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.engine.DualEngineGraphQLCoordinator_littlespidy;
import com.littlespidy.jssourcemapexplorer.engine.GraphQLRepeaterService_littlespidy;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredGraphQLOperation;
import com.littlespidy.jssourcemapexplorer.model.JsDataStore;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dedicated top-level Suite tab for GraphQL discovery and security testing.
 *
 * Provides:
 * 1. Filterable operations table by Type (Query, Mutation, Subscription, Fragment),
 *    Risk level (Critical Mutation, Sensitive Fields, Standard), and Detection Engine.
 * 2. Side-by-side formatted GraphQL query and synthesized mock variables viewer.
 * 3. 1-click dispatch to Burp Repeater (both POST JSON and GET URL-encoded).
 * 4. Client-side SDL schema reconstruction export.
 *
 * @author littlespidy
 */
public class GraphQLInspectorPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final JsDataStore dataStore;
    private final GraphQLRepeaterService_littlespidy repeaterService;

    // Master Scripts Table (Scripts with GraphQL Findings)
    private final GraphQLScriptsTableModel scriptsTableModel = new GraphQLScriptsTableModel();
    private final JTable scriptsTable = new JTable(scriptsTableModel);

    // Operations Table
    private final GraphQLOperationsTableModel opsTableModel = new GraphQLOperationsTableModel();
    private final JTable opsTable = new JTable(opsTableModel);

    // Filter Controls
    private final JButton loadHistoryBtn = new JButton("Load Proxy History");
    private final JButton runGraphQLBtn = new JButton("Run");
    private final AtomicBoolean isDiscovering = new AtomicBoolean(false);
    private Runnable onGraphQLFinished;
    private final JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-Scope Only", true);
    private final MultiSelectFilterButton domainFilterBtn;
    private final Set<String> knownDomains = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

    private final JComboBox<String> typeFilter = new JComboBox<>(new String[]{
        "All Types", "Query Only", "Mutation Only", "Subscription Only", "Fragment Only"
    });

    private final JComboBox<String> riskFilter = new JComboBox<>(new String[]{
        "All Risks", "Critical / Sensitive Only", "Standard Only"
    });

    private final JComboBox<String> engineFilter = new JComboBox<>(new String[]{
        "All Engines", "Native Java Only", "Babel AST Only", "Dual Engine Only"
    });

    private final JTextField searchField = new JTextField(16);
    private final JLabel statsLabel = new JLabel("Operations: 0 | Queries: 0 | Mutations: 0 | Subscriptions: 0 | Fragments: 0");

    // Detail Viewers
    private final JTextArea queryTextArea = new JTextArea();
    private final JTextArea variablesTextArea = new JTextArea();

    // Data Cache
    private final List<JsFileEntry> entriesWithGraphQL = new ArrayList<>();
    private final List<DiscoveredGraphQLOperation> allOperations = new ArrayList<>();
    private final List<DiscoveredGraphQLOperation> displayedOperations = new ArrayList<>();
    private JsFileEntry selectedEntry = null;

    private Runnable historyLoader;

    public GraphQLInspectorPanel_littlespidy(MontoyaApi api, JsDataStore dataStore) {
        this.api = api;
        this.dataStore = dataStore;
        this.repeaterService = new GraphQLRepeaterService_littlespidy(api);
        this.domainFilterBtn = new MultiSelectFilterButton("Domains", List.of("All Domains"), sel -> applyFilters());

        setLayout(new BorderLayout());

        add(createTopToolbar(), BorderLayout.NORTH);
        add(createCenterSplit(), BorderLayout.CENTER);

        setupTableListeners();
    }

    public void setHistoryLoader(Runnable loader) {
        this.historyLoader = loader;
    }

    public void setOnGraphQLFinished(Runnable callback) {
        this.onGraphQLFinished = callback;
    }

    public void setHistoryLoading(boolean loading) {
        loadHistoryBtn.setEnabled(!loading);
        loadHistoryBtn.setText(loading ? "Loading Proxy..." : "Load Proxy History");
    }

    public void setInScopeOnly(boolean inScope) {
        if (inScopeOnlyCheckBox.isSelected() != inScope) {
            inScopeOnlyCheckBox.setSelected(inScope);
            applyFilters();
        }
    }

    private JPanel createTopToolbar() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        loadHistoryBtn.addActionListener(e -> {
            if (historyLoader != null) historyLoader.run();
        });
        leftPanel.add(loadHistoryBtn);

        inScopeOnlyCheckBox.addActionListener(e -> applyFilters());
        leftPanel.add(inScopeOnlyCheckBox);

        leftPanel.add(domainFilterBtn);

        leftPanel.add(new JLabel("Type:"));
        typeFilter.addActionListener(e -> applyFilters());
        leftPanel.add(typeFilter);

        leftPanel.add(new JLabel("Risk:"));
        riskFilter.addActionListener(e -> applyFilters());
        leftPanel.add(riskFilter);

        leftPanel.add(new JLabel("Engine:"));
        engineFilter.addActionListener(e -> applyFilters());
        leftPanel.add(engineFilter);

        leftPanel.add(new JLabel("Search:"));
        searchField.setToolTipText("Filter by operation name, query text, endpoint, or variable");
        searchField.addActionListener(e -> applyFilters());
        leftPanel.add(searchField);

        JButton clearFilterBtn = new JButton("Reset Filters");
        clearFilterBtn.addActionListener(e -> {
            typeFilter.setSelectedIndex(0);
            riskFilter.setSelectedIndex(0);
            engineFilter.setSelectedIndex(0);
            searchField.setText("");
            domainFilterBtn.selectAll();
            applyFilters();
        });
        leftPanel.add(clearFilterBtn);

        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 2));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        rightPanel.add(statsLabel);
        rightPanel.add(new JSeparator(SwingConstants.VERTICAL));

        runGraphQLBtn.setToolTipText("Run GraphQL operation discovery on discovered JavaScript assets");
        runGraphQLBtn.addActionListener(e -> runGraphQLDiscovery());
        rightPanel.add(runGraphQLBtn);

        panel.add(leftPanel, BorderLayout.WEST);
        panel.add(rightPanel, BorderLayout.EAST);
        return panel;
    }

    private JComponent createCenterSplit() {
        // Upper Panel: Scripts Table (Left) + Operations Table (Right)
        JPanel scriptsPanel = new JPanel(new BorderLayout());
        scriptsPanel.setBorder(BorderFactory.createTitledBorder("Scripts with GraphQL"));
        scriptsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scriptsTable.setRowHeight(22);
        scriptsPanel.add(new JScrollPane(scriptsTable), BorderLayout.CENTER);

        JButton allScriptsBtn = new JButton("Show All Scripts");
        allScriptsBtn.addActionListener(e -> {
            scriptsTable.clearSelection();
            selectedEntry = null;
            applyFilters();
        });
        scriptsPanel.add(allScriptsBtn, BorderLayout.SOUTH);

        JPanel opsPanel = new JPanel(new BorderLayout());
        opsPanel.setBorder(BorderFactory.createTitledBorder("Discovered GraphQL Operations"));
        opsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        opsTable.setRowHeight(22);
        configureOpsTableRenderers();
        opsPanel.add(new JScrollPane(opsTable), BorderLayout.CENTER);

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scriptsPanel, opsPanel);
        topSplit.setDividerLocation(340);
        topSplit.setResizeWeight(0.25);

        // Lower Panel: Query Body (Left) + Variables JSON (Right)
        JPanel queryViewPanel = new JPanel(new BorderLayout());
        queryViewPanel.setBorder(BorderFactory.createTitledBorder("GraphQL Query / Mutation"));
        queryTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        queryTextArea.setEditable(false);
        queryTextArea.setTabSize(2);
        queryViewPanel.add(new JScrollPane(queryTextArea), BorderLayout.CENTER);

        JPanel varsViewPanel = new JPanel(new BorderLayout());
        varsViewPanel.setBorder(BorderFactory.createTitledBorder("Synthesized Mock Variables (Editable JSON)"));
        variablesTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        variablesTextArea.setTabSize(2);
        varsViewPanel.add(new JScrollPane(variablesTextArea), BorderLayout.CENTER);

        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, queryViewPanel, varsViewPanel);
        bottomSplit.setDividerLocation(550);
        bottomSplit.setResizeWeight(0.55);

        // Action Toolbar below Detail Viewers
        JPanel actionToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton sendPostBtn = new JButton("Send to Repeater (POST)");
        sendPostBtn.setToolTipText("Synthesizes a JSON POST request and opens it in Burp Repeater");
        sendPostBtn.addActionListener(e -> sendSelectedToRepeater(true));
        actionToolbar.add(sendPostBtn);

        JButton sendGetBtn = new JButton("Send to Repeater (GET)");
        sendGetBtn.setToolTipText("Synthesizes a GET request with URL-encoded query parameters to test for CSRF or caching issues");
        sendGetBtn.addActionListener(e -> sendSelectedToRepeater(false));
        actionToolbar.add(sendGetBtn);

        JButton copyQueryBtn = new JButton("Copy Query");
        copyQueryBtn.addActionListener(e -> copySelectedQuery());
        actionToolbar.add(copyQueryBtn);

        JButton copyJsonBtn = new JButton("Copy JSON Request Body");
        copyJsonBtn.addActionListener(e -> copySelectedJsonBody());
        actionToolbar.add(copyJsonBtn);

        JButton copyCurlBtn = new JButton("Copy as cURL");
        copyCurlBtn.addActionListener(e -> copySelectedAsCurl());
        actionToolbar.add(copyCurlBtn);

        JButton exportSdlBtn = new JButton("Export Reconstructed SDL (.graphql)...");
        exportSdlBtn.setToolTipText("Aggregates all discovered queries, mutations, and fragments into a client-side SDL schema file");
        exportSdlBtn.addActionListener(e -> exportReconstructedSdl());
        actionToolbar.add(exportSdlBtn);

        JPanel bottomContainer = new JPanel(new BorderLayout());
        bottomContainer.add(bottomSplit, BorderLayout.CENTER);
        bottomContainer.add(actionToolbar, BorderLayout.SOUTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, bottomContainer);
        mainSplit.setDividerLocation(380);
        mainSplit.setResizeWeight(0.50);

        return mainSplit;
    }

    private void configureOpsTableRenderers() {
        opsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    int modelRow = table.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < displayedOperations.size()) {
                        DiscoveredGraphQLOperation op = displayedOperations.get(modelRow);
                        if ("Critical Mutation".equalsIgnoreCase(op.riskCategory())) {
                            c.setForeground(new Color(180, 20, 20));
                            c.setFont(c.getFont().deriveFont(Font.BOLD));
                        } else if ("Sensitive Fields".equalsIgnoreCase(op.riskCategory())) {
                            c.setForeground(new Color(180, 110, 0));
                            c.setFont(c.getFont().deriveFont(Font.PLAIN));
                        } else {
                            c.setForeground(table.getForeground());
                            c.setFont(c.getFont().deriveFont(Font.PLAIN));
                        }
                    }
                }
                return c;
            }
        });
    }

    private void setupTableListeners() {
        scriptsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int r = scriptsTable.getSelectedRow();
            if (r >= 0) {
                int modelRow = scriptsTable.convertRowIndexToModel(r);
                selectedEntry = scriptsTableModel.getEntryAt(modelRow);
            } else {
                selectedEntry = null;
            }
            applyFilters();
        });

        opsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int r = opsTable.getSelectedRow();
            if (r >= 0) {
                int modelRow = opsTable.convertRowIndexToModel(r);
                if (modelRow >= 0 && modelRow < displayedOperations.size()) {
                    DiscoveredGraphQLOperation op = displayedOperations.get(modelRow);
                    queryTextArea.setText(op.queryBody());
                    queryTextArea.setCaretPosition(0);
                    variablesTextArea.setText(op.variablesJson());
                    variablesTextArea.setCaretPosition(0);
                    return;
                }
            }
            queryTextArea.setText("");
            variablesTextArea.setText("");
        });

        // Double click to send to Repeater
        opsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    sendSelectedToRepeater(true);
                } else if (SwingUtilities.isRightMouseButton(e)) {
                    int r = opsTable.rowAtPoint(e.getPoint());
                    if (r >= 0) {
                        opsTable.setRowSelectionInterval(r, r);
                        showOpsContextMenu(e);
                    }
                }
            }
        });
    }

    private void showOpsContextMenu(MouseEvent e) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem postItem = new JMenuItem("Send to Repeater (POST)");
        postItem.addActionListener(ev -> sendSelectedToRepeater(true));
        menu.add(postItem);

        JMenuItem getItem = new JMenuItem("Send to Repeater (GET)");
        getItem.addActionListener(ev -> sendSelectedToRepeater(false));
        menu.add(getItem);

        menu.addSeparator();

        JMenuItem copyQuery = new JMenuItem("Copy Query");
        copyQuery.addActionListener(ev -> copySelectedQuery());
        menu.add(copyQuery);

        JMenuItem copyJson = new JMenuItem("Copy JSON Body");
        copyJson.addActionListener(ev -> copySelectedJsonBody());
        menu.add(copyJson);

        JMenuItem copyCurl = new JMenuItem("Copy as cURL");
        copyCurl.addActionListener(ev -> copySelectedAsCurl());
        menu.add(copyCurl);

        menu.show(opsTable, e.getX(), e.getY());
    }

    // ── On-Demand GraphQL Discovery Execution ─────────────────────────────────
    public void runGraphQLDiscovery() {
        if (isDiscovering.get()) {
            JOptionPane.showMessageDialog(this, "GraphQL discovery is already in progress.", "Discovery In Progress", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<JsFileEntry> entries = dataStore != null ? dataStore.getEntries() : Collections.emptyList();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No JavaScript files available for GraphQL discovery. Please load Proxy history or send requests first.", "GraphQL Discovery", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        isDiscovering.set(true);
        runGraphQLBtn.setEnabled(false);
        runGraphQLBtn.setText("Running...");

        SwingWorker<Void, Integer> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                int total = entries.size();
                int numThreads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
                ExecutorService pool = Executors.newFixedThreadPool(numThreads);
                AtomicInteger processed = new AtomicInteger(0);

                try {
                    List<Future<?>> futures = new ArrayList<>(total);
                    for (JsFileEntry entry : entries) {
                        futures.add(pool.submit(() -> {
                            try {
                                if (entry.getResponse() != null) {
                                    String code = entry.getResponse().bodyToString();
                                    var gqlOps = DualEngineGraphQLCoordinator_littlespidy.extractOperations(entry.getUrl(), "JS File", code);
                                    entry.setJsGraphQLOperations(gqlOps);
                                }
                            } catch (Exception ignored) {}
                            int count = processed.incrementAndGet();
                            publish(count);
                        }));
                    }
                    for (var f : futures) {
                        try { f.get(); } catch (Exception ignored) {}
                    }
                } finally {
                    pool.shutdownNow();
                }
                return null;
            }

            @Override
            protected void process(List<Integer> chunks) {
                if (!chunks.isEmpty()) {
                    int done = chunks.get(chunks.size() - 1);
                    statsLabel.setText(String.format("Discovering GraphQL operations (%d / %d)...", done, entries.size()));
                }
            }

            @Override
            protected void done() {
                isDiscovering.set(false);
                runGraphQLBtn.setEnabled(true);
                runGraphQLBtn.setText("Run");
                refreshFromDataStore();
                if (onGraphQLFinished != null) {
                    onGraphQLFinished.run();
                }
            }
        };

        worker.execute();
    }

    public synchronized void refreshFromDataStore() {
        entriesWithGraphQL.clear();
        allOperations.clear();
        knownDomains.clear();

        for (JsFileEntry entry : dataStore.getEntries()) {
            if (entry.getHost() != null && !entry.getHost().isBlank()) {
                knownDomains.add(entry.getHost());
            }

            List<DiscoveredGraphQLOperation> ops = new ArrayList<>(entry.getJsGraphQLOperations());
            if (entry.getUnpackedProject() != null) {
                ops.addAll(entry.getUnpackedProject().getAllGraphQLOperations());
            }

            if (!ops.isEmpty()) {
                entriesWithGraphQL.add(entry);
                allOperations.addAll(ops);
            }
        }

        domainFilterBtn.setOptions(new ArrayList<>(knownDomains), true);
        applyFilters();
    }

    private void applyFilters() {
        boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();
        Set<String> selectedDomains = domainFilterBtn.getSelected();
        String selectedType = (String) typeFilter.getSelectedItem();
        String selectedRisk = (String) riskFilter.getSelectedItem();
        String selectedEngine = (String) engineFilter.getSelectedItem();
        String query = searchField.getText().trim().toLowerCase(Locale.ROOT);

        // Filter scripts
        List<JsFileEntry> filteredScripts = new ArrayList<>();
        for (JsFileEntry entry : entriesWithGraphQL) {
            if (inScopeOnly && api != null && !api.scope().isInScope(entry.getUrl())) {
                continue;
            }
            if (!domainFilterBtn.isAllSelected() && !MultiSelectFilterButton.matchesDomain(entry.getHost(), selectedDomains)) {
                continue;
            }
            filteredScripts.add(entry);
        }
        scriptsTableModel.setEntries(filteredScripts);

        // Filter operations
        displayedOperations.clear();
        int queryCount = 0;
        int mutationCount = 0;
        int subCount = 0;
        int fragCount = 0;

        for (DiscoveredGraphQLOperation op : allOperations) {
            if (selectedEntry != null && !op.sourceLocation().equals(selectedEntry.getUrl())) {
                continue;
            }

            if (inScopeOnly && api != null && !api.scope().isInScope(op.sourceLocation())) {
                continue;
            }

            if (selectedType != null && !selectedType.equals("All Types")) {
                String typeName = selectedType.replace(" Only", "");
                if (!op.operationType().equalsIgnoreCase(typeName)) {
                    continue;
                }
            }

            if (selectedRisk != null && !selectedRisk.equals("All Risks")) {
                if (selectedRisk.startsWith("Critical") && !"Critical Mutation".equalsIgnoreCase(op.riskCategory()) && !"Sensitive Fields".equalsIgnoreCase(op.riskCategory())) {
                    continue;
                } else if (selectedRisk.startsWith("Standard") && !"Standard".equalsIgnoreCase(op.riskCategory())) {
                    continue;
                }
            }

            if (selectedEngine != null && !selectedEngine.equals("All Engines")) {
                if (selectedEngine.startsWith("Native") && !op.detectionEngine().contains("Native")) {
                    continue;
                } else if (selectedEngine.startsWith("Babel") && !op.detectionEngine().contains("Babel")) {
                    continue;
                } else if (selectedEngine.startsWith("Dual") && !op.detectionEngine().contains("Dual")) {
                    continue;
                }
            }

            if (!query.isEmpty()) {
                boolean matches = (op.operationName() != null && op.operationName().toLowerCase(Locale.ROOT).contains(query))
                    || (op.queryBody() != null && op.queryBody().toLowerCase(Locale.ROOT).contains(query))
                    || (op.associatedEndpoint() != null && op.associatedEndpoint().toLowerCase(Locale.ROOT).contains(query))
                    || (op.sourceLocation() != null && op.sourceLocation().toLowerCase(Locale.ROOT).contains(query));
                if (!matches) continue;
            }

            displayedOperations.add(op);
            if ("Query".equalsIgnoreCase(op.operationType())) queryCount++;
            else if ("Mutation".equalsIgnoreCase(op.operationType())) mutationCount++;
            else if ("Subscription".equalsIgnoreCase(op.operationType())) subCount++;
            else if ("Fragment".equalsIgnoreCase(op.operationType())) fragCount++;
        }

        opsTableModel.setOperations(displayedOperations);
        statsLabel.setText(String.format("Operations: %d | Queries: %d | Mutations: %d | Subscriptions: %d | Fragments: %d",
            displayedOperations.size(), queryCount, mutationCount, subCount, fragCount));

        if (displayedOperations.isEmpty()) {
            queryTextArea.setText("");
            variablesTextArea.setText("");
        } else {
            opsTable.setRowSelectionInterval(0, 0);
        }
    }

    private void sendSelectedToRepeater(boolean isPost) {
        int r = opsTable.getSelectedRow();
        if (r < 0) {
            JOptionPane.showMessageDialog(this, "Please select an operation first.", "Send to Repeater", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = opsTable.convertRowIndexToModel(r);
        DiscoveredGraphQLOperation op = displayedOperations.get(modelRow);

        // Apply any live edits from variables text area
        String currentVars = variablesTextArea.getText();
        if (currentVars != null && !currentVars.isBlank()) {
            op = new DiscoveredGraphQLOperation(
                op.sourceLocation(), op.sourceType(), op.operationName(), op.operationType(),
                op.queryBody(), op.variables(), currentVars, op.associatedEndpoint(),
                op.detectionEngine(), op.detectionTechnique(), op.riskCategory(),
                op.line(), op.startOffset(), op.endOffset(), op.snippet()
            );
        }

        JsFileEntry hostEntry = findEntryForOperation(op);
        if (isPost) {
            repeaterService.sendToRepeaterPost(op, hostEntry);
        } else {
            repeaterService.sendToRepeaterGet(op, hostEntry);
        }
    }

    private JsFileEntry findEntryForOperation(DiscoveredGraphQLOperation op) {
        for (JsFileEntry entry : entriesWithGraphQL) {
            if (entry.getUrl().equals(op.sourceLocation())) return entry;
        }
        return null;
    }

    private void copySelectedQuery() {
        int r = opsTable.getSelectedRow();
        if (r >= 0) {
            DiscoveredGraphQLOperation op = displayedOperations.get(opsTable.convertRowIndexToModel(r));
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(op.queryBody()), null);
            JOptionPane.showMessageDialog(this, "GraphQL Query copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void copySelectedJsonBody() {
        int r = opsTable.getSelectedRow();
        if (r >= 0) {
            DiscoveredGraphQLOperation op = displayedOperations.get(opsTable.convertRowIndexToModel(r));
            String vars = variablesTextArea.getText().isBlank() ? "{}" : variablesTextArea.getText().trim();
            String json = "{\n  \"query\": \"" + op.queryBody().replace("\"", "\\\"").replace("\n", "\\n") + "\",\n  \"variables\": " + vars + "\n}";
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(json), null);
            JOptionPane.showMessageDialog(this, "JSON Request Body copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void copySelectedAsCurl() {
        int r = opsTable.getSelectedRow();
        if (r >= 0) {
            DiscoveredGraphQLOperation op = displayedOperations.get(opsTable.convertRowIndexToModel(r));
            JsFileEntry entry = findEntryForOperation(op);
            String url = (entry != null && entry.getRequest() != null && entry.getRequest().httpService() != null)
                ? (entry.getRequest().httpService().secure() ? "https" : "http") + "://" + entry.getRequest().httpService().host() + op.associatedEndpoint()
                : "https://localhost" + op.associatedEndpoint();

            String vars = variablesTextArea.getText().isBlank() ? "{}" : variablesTextArea.getText().trim();
            String body = "{\"query\":\"" + op.queryBody().replace("\"", "\\\"").replace("\n", " ") + "\",\"variables\":" + vars + "}";
            String curl = "curl -i -s -k -X POST \"" + url + "\" \\\n" +
                "  -H \"Content-Type: application/json\" \\\n" +
                "  -d '" + body.replace("'", "'\\''") + "'";

            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(curl), null);
            JOptionPane.showMessageDialog(this, "cURL command copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void exportReconstructedSdl() {
        if (allOperations.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No GraphQL operations discovered yet to reconstruct schema.", "Export SDL", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("client_reconstructed_schema.graphql"));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("# Client-Side Reconstructed GraphQL Schema\n");
                sb.append("# Generated by JavaScript Inspector (littlespidy)\n\n");

                Set<String> seenQueries = new LinkedHashSet<>();
                for (DiscoveredGraphQLOperation op : allOperations) {
                    if (seenQueries.add(op.queryBody().trim())) {
                        sb.append("# Operation: ").append(op.operationName())
                          .append(" (").append(op.operationType()).append(")")
                          .append(" - Found in: ").append(op.sourceLocation()).append("\n");
                        sb.append(op.queryBody()).append("\n\n");
                    }
                }

                Files.writeString(target.toPath(), sb.toString(), StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this, "Successfully exported " + seenQueries.size() + " operations to:\n" + target.getAbsolutePath(), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to export SDL: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ── Table Models ──

    private static class GraphQLScriptsTableModel extends AbstractTableModel {
        private final String[] columns = {"Host", "Path", "GraphQL Ops", "Framework"};
        private final List<JsFileEntry> entries = new ArrayList<>();

        public void setEntries(List<JsFileEntry> list) {
            entries.clear();
            if (list != null) entries.addAll(list);
            fireTableDataChanged();
        }

        public JsFileEntry getEntryAt(int r) {
            return (r >= 0 && r < entries.size()) ? entries.get(r) : null;
        }

        @Override public int getRowCount() { return entries.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int c) { return columns[c]; }

        @Override
        public Object getValueAt(int r, int c) {
            JsFileEntry e = entries.get(r);
            int opsCount = e.getJsGraphQLOperations().size() + (e.getUnpackedProject() != null ? e.getUnpackedProject().getAllGraphQLOperations().size() : 0);
            return switch (c) {
                case 0 -> e.getHost();
                case 1 -> e.getPath();
                case 2 -> opsCount;
                case 3 -> e.getFramework();
                default -> "";
            };
        }
    }

    private static class GraphQLOperationsTableModel extends AbstractTableModel {
        private final String[] columns = {"Name", "Type", "Risk", "Engine", "Technique", "Endpoint", "Line"};
        private final List<DiscoveredGraphQLOperation> ops = new ArrayList<>();

        public void setOperations(List<DiscoveredGraphQLOperation> list) {
            ops.clear();
            if (list != null) ops.addAll(list);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return ops.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int c) { return columns[c]; }

        @Override
        public Object getValueAt(int r, int c) {
            DiscoveredGraphQLOperation op = ops.get(r);
            return switch (c) {
                case 0 -> op.operationName();
                case 1 -> op.operationType();
                case 2 -> op.riskCategory();
                case 3 -> op.detectionEngine();
                case 4 -> op.detectionTechnique();
                case 5 -> op.associatedEndpoint();
                case 6 -> op.line();
                default -> "";
            };
        }
    }
}
