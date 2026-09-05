// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InScopeDomainManager;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Reusable findings panel supporting master-detail layout, multi-select toolbar filters,
 * in-scope domain selection, live ingestion progress bar, deep-linking navigation quad,
 * inter-tool integration (Repeater/Intruder/Organizer), and row pinning.
 */
public class CategoryFindingsPanel extends JPanel {

    private final MontoyaApi api;
    private final FindingCategory category;
    private final InspectorDataStore dataStore;
    private final ResponseScanEngine scanEngine;
    private final InScopeDomainManager domainManager;
    private final Runnable refreshAllTabsCallback;

    private final FindingsTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<FindingsTableModel> sorter;

    private final HttpRequestEditor reqEditor;
    private final HttpResponseEditor respEditor;
    private final JTabbedPane editorTabs;

    private final JLabel statsLabel;
    private final JLabel liveStatusLabel;
    private final JProgressBar progressBar;
    private final JTextField searchField;
    private final JCheckBox inScopeCb;
    private final JButton inScopeDomainsBtn;
    private final MultiSelectFilterButton methodFilterBtn;
    private final MultiSelectFilterButton statusFilterBtn;
    private final MultiSelectFilterButton contentTypeFilterBtn;
    private final MultiSelectFilterButton secretTypeFilterBtn;
    private final JButton loadHistoryBtn;
    private JButton configPasswordsBtn;

    public CategoryFindingsPanel(
            MontoyaApi api,
            FindingCategory category,
            InspectorDataStore dataStore,
            ResponseScanEngine scanEngine,
            InScopeDomainManager domainManager,
            Runnable refreshAllTabsCallback
    ) {
        this.api = api;
        this.category = category;
        this.dataStore = dataStore;
        this.scanEngine = scanEngine;
        this.domainManager = domainManager;
        this.refreshAllTabsCallback = refreshAllTabsCallback;

        setLayout(new BorderLayout());

        // Table Model & Sorter
        tableModel = new FindingsTableModel(dataStore);
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        // Styling & Renderers
        table.getColumnModel().getColumn(0).setPreferredWidth(45);  // #
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(35);  // Pin
        table.getColumnModel().getColumn(1).setMaxWidth(45);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);  // Method
        table.getColumnModel().getColumn(2).setMaxWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(60);  // Status
        table.getColumnModel().getColumn(3).setMaxWidth(75);
        table.getColumnModel().getColumn(3).setCellRenderer(new StatusCodeRenderer());
        table.getColumnModel().getColumn(4).setPreferredWidth(160); // Type
        table.getColumnModel().getColumn(5).setPreferredWidth(220); // Match
        table.getColumnModel().getColumn(6).setPreferredWidth(110); // Location
        table.getColumnModel().getColumn(7).setPreferredWidth(65);  // Length
        table.getColumnModel().getColumn(8).setPreferredWidth(100); // Content-Type
        table.getColumnModel().getColumn(9).setPreferredWidth(320); // URL
        table.getColumnModel().getColumn(10).setPreferredWidth(70); // Time

        // Montoya Built-in Editors (Pretty/Raw/Hex)
        reqEditor = api.userInterface().createHttpRequestEditor();
        respEditor = api.userInterface().createHttpResponseEditor();

        editorTabs = new JTabbedPane();
        editorTabs.addTab("Request", reqEditor.uiComponent());
        editorTabs.addTab("Response", respEditor.uiComponent());

        // Deep-Linking Table Selection Listener (Auto-Switch, Marker, Search, Caret Scroll)
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    FindingEntry entry = tableModel.getEntryAt(modelRow);
                    if (entry != null) {
                        navigateToFinding(entry);
                    }
                }
            }
        });

        // Top Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        loadHistoryBtn = new JButton("Load Proxy History");
        loadHistoryBtn.setFont(loadHistoryBtn.getFont().deriveFont(Font.BOLD));
        loadHistoryBtn.setToolTipText("Scan all HTTP responses currently in Burp Proxy history");
        loadHistoryBtn.addActionListener(e -> runProxyHistoryScan());
        toolbar.add(loadHistoryBtn);

        // Prominent Password Configuration Button on Password tab
        if (category == FindingCategory.PASSWORD) {
            configPasswordsBtn = new JButton(getPasswordButtonLabel());
            configPasswordsBtn.setFont(configPasswordsBtn.getFont().deriveFont(Font.BOLD));
            configPasswordsBtn.setToolTipText("Configure target passwords to scan for in responses");
            configPasswordsBtn.addActionListener(e -> openPasswordConfigDialog());
            toolbar.add(configPasswordsBtn);
        }

        toolbar.add(new JSeparator(JSeparator.VERTICAL));

        inScopeDomainsBtn = new JButton(getDomainButtonLabel());
        inScopeDomainsBtn.setToolTipText("Select specific in-scope target domains to include/exclude");
        inScopeDomainsBtn.setEnabled(false);
        inScopeDomainsBtn.addActionListener(e -> openInScopeDomainDialog());

        inScopeCb = new JCheckBox("In-Scope Only");
        inScopeCb.addActionListener(e -> {
            inScopeDomainsBtn.setEnabled(inScopeCb.isSelected());
            refreshView();
        });
        toolbar.add(inScopeCb);
        toolbar.add(inScopeDomainsBtn);

        toolbar.add(new JSeparator(JSeparator.VERTICAL));

        if (category == FindingCategory.SECRET) {
            List<String> secretTypes = new ArrayList<>();
            secretTypes.add("All Secret Types");
            secretTypes.addAll(scanEngine.getSecretScanner().getRuleNames());
            secretTypeFilterBtn = new MultiSelectFilterButton(
                    "Secret Type",
                    secretTypes,
                    sel -> refreshView()
            );
            toolbar.add(secretTypeFilterBtn);
        } else {
            secretTypeFilterBtn = null;
        }

        methodFilterBtn = new MultiSelectFilterButton(
                "Method",
                List.of("All Methods", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"),
                sel -> refreshView()
        );
        toolbar.add(methodFilterBtn);

        statusFilterBtn = new MultiSelectFilterButton(
                "Status",
                List.of("All Status Codes", "2xx", "200", "3xx", "301", "302", "4xx", "401", "403", "404", "5xx", "500"),
                sel -> refreshView()
        );
        toolbar.add(statusFilterBtn);

        contentTypeFilterBtn = new MultiSelectFilterButton(
                "Content-Type",
                List.of("All Types", "JSON", "HTML", "JavaScript", "XML", "Plain"),
                sel -> refreshView()
        );
        toolbar.add(contentTypeFilterBtn);

        toolbar.add(new JLabel("Search:"));
        searchField = new JTextField(12);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { refreshView(); }
            @Override
            public void removeUpdate(DocumentEvent e) { refreshView(); }
            @Override
            public void changedUpdate(DocumentEvent e) { refreshView(); }
        });
        toolbar.add(searchField);

        JButton pinBtn = new JButton("Pin Selected");
        pinBtn.setToolTipText("Show only selected rows, isolating them from general filters");
        pinBtn.addActionListener(e -> pinSelectedRows());
        toolbar.add(pinBtn);

        JButton clearPinsBtn = new JButton("Clear Pins");
        clearPinsBtn.addActionListener(e -> {
            dataStore.clearPins();
            refreshView();
        });
        toolbar.add(clearPinsBtn);

        JButton clearDataBtn = new JButton("Clear");
        clearDataBtn.addActionListener(e -> {
            dataStore.clear();
            refreshView();
        });
        toolbar.add(clearDataBtn);

        JButton exportTsvBtn = new JButton("Export TSV");
        exportTsvBtn.setToolTipText("Export currently displayed findings to a Tab-Separated Values (.tsv) file");
        exportTsvBtn.addActionListener(e -> exportFindingsToTsv());
        toolbar.add(exportTsvBtn);

        statsLabel = new JLabel("Total: 0 | Displayed: 0");
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.BOLD));
        toolbar.add(statsLabel);

        // Dedicated Live Ingestion Status Strip (WEST: status label, EAST: progress bar)
        JPanel statusRow = new JPanel(new BorderLayout(6, 2));
        statusRow.setBorder(BorderFactory.createEmptyBorder(2, 8, 4, 8));

        liveStatusLabel = new JLabel("Ready. Click 'Load Proxy History' to begin analysis.");
        liveStatusLabel.setFont(liveStatusLabel.getFont().deriveFont(Font.PLAIN, 12f));

        progressBar = new JProgressBar();
        progressBar.setPreferredSize(new Dimension(240, 18));
        progressBar.setVisible(false);

        statusRow.add(liveStatusLabel, BorderLayout.WEST);
        statusRow.add(progressBar, BorderLayout.EAST);

        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.add(toolbar, BorderLayout.NORTH);
        topContainer.add(statusRow, BorderLayout.SOUTH);

        add(topContainer, BorderLayout.NORTH);

        // Master-Detail Split Pane
        JScrollPane tableScroll = new JScrollPane(table);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorTabs);
        splitPane.setResizeWeight(0.55);
        splitPane.setDividerLocation(320);

        add(splitPane, BorderLayout.CENTER);

        // Context Menu & Shortcuts
        setupContextMenu();
        setupClipboardShortcut();

        // Initial populate
        refreshView();
    }

    public void refreshView() {
        boolean inScope = inScopeCb.isSelected();
        String search = searchField.getText();
        Set<String> methods = methodFilterBtn.getSelected();
        Set<String> statuses = statusFilterBtn.getSelected();
        Set<String> contentTypes = contentTypeFilterBtn.getSelected();
        Set<String> patterns = secretTypeFilterBtn != null ? secretTypeFilterBtn.getSelected() : null;

        List<FindingEntry> filtered = dataStore.getFilteredEntries(
                search,
                statuses,
                contentTypes,
                methods,
                patterns,
                inScope,
                url -> api.scope().isInScope(url),
                domainManager
        );

        tableModel.setEntries(filtered);

        String stats;
        if (dataStore.hasPins()) {
            stats = "Pinned: " + dataStore.getPinnedCount() + " / " + dataStore.size();
        } else {
            stats = "Total: " + dataStore.size() + " | Displayed: " + filtered.size();
        }
        statsLabel.setText(stats);

        inScopeDomainsBtn.setText(getDomainButtonLabel());
        inScopeDomainsBtn.setEnabled(inScope);

        if (configPasswordsBtn != null) {
            configPasswordsBtn.setText(getPasswordButtonLabel());
        }
    }

    // ─── Deep-Linking Quad Navigation Engine ─────────────────────────────────────

    private void navigateToFinding(FindingEntry finding) {
        if (finding == null || finding.requestResponse() == null) return;

        HttpRequestResponse message = finding.requestResponse();
        String query = finding.matchValue();

        if (finding.isResponseFinding()) {
            HttpResponse response = message.response();
            if (response == null) return;

            // Pillar 1: Active Tab Auto-Switching to Response
            editorTabs.setSelectedComponent(respEditor.uiComponent());

            // Calculate absolute raw message offset if relative to body
            int rawStart = finding.startOffset();
            int rawEnd = finding.endOffset();
            int bodyOffset = response.bodyOffset();

            if (rawStart >= 0 && rawEnd > rawStart) {
                if (!finding.isHeaderFinding()) {
                    rawStart += bodyOffset;
                    rawEnd += bodyOffset;
                }
            } else if (query != null && !query.isEmpty()) {
                // Fallback: Locate query inside raw response string
                String rawStr = response.toString();
                int idx = rawStr.indexOf(query);
                if (idx >= 0) {
                    rawStart = idx;
                    rawEnd = idx + query.length();
                }
            }

            // Pillar 2: Apply Native Montoya Markers
            if (rawStart >= 0 && rawEnd > rawStart && rawEnd <= response.toByteArray().length()) {
                try {
                    Marker marker = Marker.marker(rawStart, rawEnd);
                    response = response.withMarkers(marker);
                } catch (Exception ignored) {}
            }
            respEditor.setResponse(response);

            // Update Request editor in background
            if (message.request() != null) {
                reqEditor.setRequest(message.request());
            }

            // Pillar 3: Search Bar Expression Populating
            if (query != null && !query.isEmpty()) {
                try {
                    respEditor.setSearchExpression(query);
                } catch (Exception ignored) {}
            }

            // Pillar 4: Caret Positioning & Viewport Auto-Scroll
            if (rawStart >= 0) {
                final int targetCaret = rawStart;
                SwingUtilities.invokeLater(() -> scrollTextComponent(respEditor.uiComponent(), targetCaret));
            }

        } else {
            // Request Finding
            HttpRequest request = message.request();
            if (request == null) return;

            // Pillar 1: Active Tab Auto-Switching to Request
            editorTabs.setSelectedComponent(reqEditor.uiComponent());

            int rawStart = finding.startOffset();
            int rawEnd = finding.endOffset();
            int bodyOffset = request.bodyOffset();

            if (rawStart >= 0 && rawEnd > rawStart) {
                if (!finding.isHeaderFinding()) {
                    rawStart += bodyOffset;
                    rawEnd += bodyOffset;
                }
            } else if (query != null && !query.isEmpty()) {
                String rawStr = request.toString();
                int idx = rawStr.indexOf(query);
                if (idx >= 0) {
                    rawStart = idx;
                    rawEnd = idx + query.length();
                }
            }

            // Pillar 2: Apply Native Montoya Markers
            if (rawStart >= 0 && rawEnd > rawStart && rawEnd <= request.toByteArray().length()) {
                try {
                    Marker marker = Marker.marker(rawStart, rawEnd);
                    request = request.withMarkers(marker);
                } catch (Exception ignored) {}
            }
            reqEditor.setRequest(request);

            if (message.response() != null) {
                respEditor.setResponse(message.response());
            }

            // Pillar 3: Search Bar Expression Populating
            if (query != null && !query.isEmpty()) {
                try {
                    reqEditor.setSearchExpression(query);
                } catch (Exception ignored) {}
            }

            // Pillar 4: Caret Positioning & Viewport Auto-Scroll
            if (rawStart >= 0) {
                final int targetCaret = rawStart;
                SwingUtilities.invokeLater(() -> scrollTextComponent(reqEditor.uiComponent(), targetCaret));
            }
        }
    }

    private static void scrollTextComponent(Component root, int position) {
        if (root == null) return;
        if (root instanceof javax.swing.text.JTextComponent tc) {
            try {
                if (position >= 0 && position <= tc.getText().length()) {
                    tc.setCaretPosition(position);
                }
            } catch (Exception ignored) {}
            return;
        }
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                scrollTextComponent(child, position);
            }
        }
    }

    // ─── Helpers & Event Handlers ────────────────────────────────────────────────

    private String getPasswordButtonLabel() {
        int count = scanEngine.getPasswordScanner().getPasswordCount();
        return "Configure Passwords... (" + count + " active)";
    }

    private String getDomainButtonLabel() {
        if (domainManager == null || domainManager.getTotalDomainCount() == 0) {
            return "In-Scope Domains...";
        }
        if (domainManager.isAllSelected()) {
            return "In-Scope Domains (All " + domainManager.getTotalDomainCount() + ")";
        }
        return "In-Scope Domains (" + domainManager.getSelectedDomainCount() + "/" + domainManager.getTotalDomainCount() + ")";
    }

    private void openInScopeDomainDialog() {
        Frame topFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        InScopeDomainDialog dialog = new InScopeDomainDialog(topFrame, domainManager, () -> {
            if (refreshAllTabsCallback != null) {
                refreshAllTabsCallback.run();
            } else {
                refreshView();
            }
        });
        dialog.setVisible(true);
    }

    private void openPasswordConfigDialog() {
        Frame topFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        PasswordConfigDialog dialog = new PasswordConfigDialog(topFrame, scanEngine.getPasswordScanner(), () -> {
            if (configPasswordsBtn != null) {
                configPasswordsBtn.setText(getPasswordButtonLabel());
            }
        });
        dialog.setVisible(true);
    }

    // ─── Proxy History Scan with Live Progress Bar ───────────────────────────────

    private record ProgressChunk(int processed, int total, int newFindings) {}

    private void runProxyHistoryScan() {
        // If password tab and no passwords set, prompt user
        if (category == FindingCategory.PASSWORD && scanEngine.getPasswordScanner().getPasswordCount() == 0) {
            int opt = JOptionPane.showConfirmDialog(
                    this,
                    "No target passwords have been configured yet.\nWould you like to configure passwords before analyzing proxy history?",
                    "Configure Passwords",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (opt == JOptionPane.YES_OPTION) {
                openPasswordConfigDialog();
            }
        }

        loadHistoryBtn.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(false);
        progressBar.setValue(0);
        liveStatusLabel.setText("Scanning Proxy history for in-scope traffic...");

        SwingWorker<Integer, ProgressChunk> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int total = history.size();
                if (total == 0) return 0;

                // 1. Discover in-scope domains from history
                for (ProxyHttpRequestResponse item : history) {
                    if (item.request() != null) {
                        String url = item.request().url();
                        if (api.scope().isInScope(url)) {
                            String host = item.request().httpService() != null ? item.request().httpService().host() : "";
                            domainManager.addDomain(host);
                        }
                    }
                }

                // 2. Multi-Threaded Ingestion Pool (Bounded by CPU cores)
                int numThreads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
                ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                AtomicInteger processed = new AtomicInteger(0);
                AtomicInteger newFindings = new AtomicInteger(0);

                try {
                    List<Future<?>> futures = new ArrayList<>(total);
                    for (ProxyHttpRequestResponse item : history) {
                        if (isCancelled()) break;
                        futures.add(executor.submit(() -> {
                            if (isCancelled()) return;
                            if (item.hasResponse()) {
                                String host = (item.request() != null && item.request().httpService() != null)
                                        ? item.request().httpService().host() : "";
                                int added = scanEngine.scanProxyItem(item);
                                if (added > 0 && !host.isBlank()) {
                                    domainManager.registerFinding(host);
                                }
                                newFindings.addAndGet(added);
                            }
                            int cur = processed.incrementAndGet();
                            if (cur % 25 == 0 || cur == total) {
                                publish(new ProgressChunk(cur, total, newFindings.get()));
                            }
                        }));
                    }

                    for (Future<?> f : futures) {
                        if (isCancelled()) break;
                        try {
                            f.get();
                        } catch (Exception ignored) {}
                    }
                } finally {
                    executor.shutdownNow();
                }

                return newFindings.get();
            }

            @Override
            protected void process(List<ProgressChunk> chunks) {
                if (!chunks.isEmpty()) {
                    ProgressChunk latest = chunks.get(chunks.size() - 1);
                    progressBar.setMaximum(latest.total());
                    progressBar.setValue(latest.processed());
                    liveStatusLabel.setText("Scanning Proxy history: " + latest.processed() + " / " + latest.total()
                            + " items (" + latest.newFindings() + " findings)...");
                }
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    liveStatusLabel.setText("Analysis complete: scanned Proxy history | Discovered " + count + " new findings.");
                    api.logging().logToOutput("Response Inspector: Proxy history analysis complete. New findings: " + count);
                } catch (Exception ex) {
                    liveStatusLabel.setText("Scan encountered an issue: " + ex.getMessage());
                } finally {
                    progressBar.setVisible(false);
                    loadHistoryBtn.setEnabled(true);
                    if (refreshAllTabsCallback != null) {
                        refreshAllTabsCallback.run();
                    } else {
                        refreshView();
                    }
                }
            }
        };

        worker.execute();
    }

    private void exportFindingsToTsv() {
        Set<String> patterns = secretTypeFilterBtn != null ? secretTypeFilterBtn.getSelected() : null;
        List<FindingEntry> currentFindings = dataStore.getFilteredEntries(
                searchField.getText(),
                statusFilterBtn.getSelected(),
                contentTypeFilterBtn.getSelected(),
                methodFilterBtn.getSelected(),
                patterns,
                inScopeCb.isSelected(),
                url -> api.scope().isInScope(url),
                domainManager
        );

        if (currentFindings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings available to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Findings as TSV");
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        fileChooser.setSelectedFile(new File(category.name().toLowerCase() + "_findings_" + timestamp + ".tsv"));

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().toLowerCase().endsWith(".tsv")) {
                fileToSave = new File(fileToSave.getParentFile(), fileToSave.getName() + ".tsv");
            }
            try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8))) {
                writer.println(FindingEntry.tsvHeader());
                for (FindingEntry entry : currentFindings) {
                    writer.println(entry.toTsvRow());
                }
                JOptionPane.showMessageDialog(this,
                        "Successfully exported " + currentFindings.size() + " findings to:\n" + fileToSave.getAbsolutePath(),
                        "Export Complete",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to export TSV: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void pinSelectedRows() {
        for (int viewRow : table.getSelectedRows()) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            FindingEntry entry = tableModel.getEntryAt(modelRow);
            if (entry != null) {
                dataStore.pin(entry.id());
            }
        }
        refreshView();
    }

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
        sendRepeater.addActionListener(e -> {
            for (int viewRow : table.getSelectedRows()) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null && entry.requestResponse() != null && entry.requestResponse().request() != null) {
                    String tabName = entry.method() + " " + entry.host() + entry.path();
                    api.repeater().sendToRepeater(entry.requestResponse().request(), tabName);
                }
            }
        });

        JMenuItem sendIntruder = new JMenuItem("Send to Intruder");
        sendIntruder.addActionListener(e -> {
            for (int viewRow : table.getSelectedRows()) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null && entry.requestResponse() != null && entry.requestResponse().request() != null) {
                    api.intruder().sendToIntruder(entry.requestResponse().request());
                }
            }
        });

        JMenuItem sendOrganizer = new JMenuItem("Send to Organizer");
        sendOrganizer.addActionListener(e -> {
            for (int viewRow : table.getSelectedRows()) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null && entry.requestResponse() != null) {
                    api.organizer().sendToOrganizer(entry.requestResponse());
                }
            }
        });

        JMenuItem copyMatch = new JMenuItem("Copy Match Excerpt");
        copyMatch.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                            new StringSelection(entry.matchValue()), null
                    );
                }
            }
        });

        JMenuItem pinItem = new JMenuItem("Pin Selected");
        pinItem.addActionListener(e -> pinSelectedRows());

        JMenuItem unpinItem = new JMenuItem("Unpin Selected");
        unpinItem.addActionListener(e -> {
            for (int viewRow : table.getSelectedRows()) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                FindingEntry entry = tableModel.getEntryAt(modelRow);
                if (entry != null) {
                    dataStore.unpin(entry.id());
                }
            }
            refreshView();
        });

        popup.add(sendRepeater);
        popup.add(sendIntruder);
        popup.add(sendOrganizer);
        popup.addSeparator();
        popup.add(copyMatch);
        JMenuItem exportTsvItem = new JMenuItem("Export Findings as TSV...");
        exportTsvItem.addActionListener(e -> exportFindingsToTsv());
        popup.add(exportTsvItem);
        popup.addSeparator();
        popup.add(pinItem);
        popup.add(unpinItem);

        table.setComponentPopupMenu(popup);
    }

    private void setupClipboardShortcut() {
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copyTsv");
        table.getActionMap().put("copyTsv", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                if (selectedRows.length == 0) return;

                StringBuilder sb = new StringBuilder();
                // Headers
                for (int c = 0; c < table.getColumnCount(); c++) {
                    sb.append(table.getColumnName(c)).append(c < table.getColumnCount() - 1 ? "\t" : "\n");
                }
                // Selected Rows
                for (int viewRow : selectedRows) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    for (int c = 0; c < table.getColumnCount(); c++) {
                        Object val = tableModel.getValueAt(modelRow, c);
                        sb.append(val != null ? val.toString().replace("\t", " ") : "");
                        sb.append(c < table.getColumnCount() - 1 ? "\t" : "\n");
                    }
                }
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
            }
        });
    }
}
