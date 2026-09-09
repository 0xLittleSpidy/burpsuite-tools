// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.engine.PostToGetEngine;
import com.littlespidy.convertposttoget.model.ConfiguredHeader;
import com.littlespidy.convertposttoget.model.ConversionResult;
import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import com.littlespidy.convertposttoget.model.PostCandidate;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated Conversion Session Panel adhering strictly to extension_architecture.md:
 * - Collapsible filter sidebar with 500px/380px expanded layout & Smart pattern suppression
 * - Multi-selection table with Row Pinning (Pin Selected / Clear Pins)
 * - Deep-Linking Quad: tab auto-switching, native Montoya Markers, search bar populating, caret auto-scroll
 * - Complete Burp Suite tool interoperability: Send to Repeater, Intruder, and Organizer
 * - Live Status Glyphs on session completion (⚠️ findings vs ✔ clear)
 * - Thread-safe streaming results with pause/resume controller
 *
 * @author littlespidy
 */
public class ConvertSessionPanel extends JPanel {
    private final MontoyaApi api;
    private final ConvertPostToGetConfig config;
    private final List<PostCandidate> targetCandidates;
    private final Consumer<ConvertSessionPanel> closeCallback;

    private final PostToGetEngine engine;
    private final ConversionResultsTableModel tableModel = new ConversionResultsTableModel();
    private final JTable resultsTable = new JTable(tableModel);

    private final ConvertFilterPanel filterPanel;
    private final JPanel sidebarContainer = new JPanel(new BorderLayout());
    private final JButton toggleSidebarBtn = new JButton("\u25c0 Filters");
    private boolean sidebarVisible = true;

    private final JButton startButton = new JButton("Start Conversion Test");
    private final JButton pauseButton = new JButton("Pause");
    private final JButton stopButton = new JButton("Stop");
    private final JButton pinSelectedBtn = new JButton("Pin Selected");
    private final JButton clearPinsBtn = new JButton("Clear Pins");
    private final JButton customHeadersButton = new JButton("Custom Headers & Auth... (0)");
    private final JButton exportTsvButton = new JButton("Export TSV...");
    private final JButton clearButton = new JButton("Clear Results");
    private final JButton optionsButton = new JButton("Options...");
    private final JLabel statusLabel = new JLabel("Ready.");

    private final List<ConfiguredHeader> sessionHeaders = new ArrayList<>();

    private final JTabbedPane editorTabs = new JTabbedPane();
    private final HttpRequestEditor convertedGetRequestEditor;
    private final HttpResponseEditor convertedGetResponseEditor;
    private final HttpRequestEditor originalPostRequestEditor;
    private final HttpResponseEditor originalPostResponseEditor;
    private final JTextArea evidenceTextArea = new JTextArea();

    private Consumer<Integer> completionGlyphCallback;

    public ConvertSessionPanel(
        MontoyaApi api,
        ConvertPostToGetConfig config,
        List<PostCandidate> targetCandidates,
        Consumer<ConvertSessionPanel> closeCallback
    ) {
        this.api = api;
        this.config = config;
        this.targetCandidates = targetCandidates;
        this.closeCallback = closeCallback;
        this.engine = new PostToGetEngine(api, config);

        setLayout(new BorderLayout(5, 5));

        // ── Montoya Pretty/Raw/Hex Editors ──
        convertedGetRequestEditor = api.userInterface().createHttpRequestEditor();
        convertedGetResponseEditor = api.userInterface().createHttpResponseEditor();
        originalPostRequestEditor = api.userInterface().createHttpRequestEditor();
        originalPostResponseEditor = api.userInterface().createHttpResponseEditor();

        if (targetCandidates != null && !targetCandidates.isEmpty()) {
            PostCandidate first = targetCandidates.get(0);
            if (first.request() != null) originalPostRequestEditor.setRequest(first.request());
            if (first.response() != null) originalPostResponseEditor.setResponse(first.response());
        }

        // ── Top Action Toolbar ──
        JPanel topBar = new JPanel(new BorderLayout(5, 5));
        topBar.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        startButton.setFont(startButton.getFont().deriveFont(Font.BOLD));
        buttonPanel.add(startButton);
        buttonPanel.add(pauseButton);
        buttonPanel.add(stopButton);
        buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
        buttonPanel.add(pinSelectedBtn);
        buttonPanel.add(clearPinsBtn);
        buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
        buttonPanel.add(customHeadersButton);
        buttonPanel.add(exportTsvButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(optionsButton);

        pauseButton.setEnabled(false);
        stopButton.setEnabled(false);

        topBar.add(buttonPanel, BorderLayout.WEST);
        statusLabel.setText("Ready to test " + (targetCandidates != null ? targetCandidates.size() : 0) + " POST target(s).");
        topBar.add(statusLabel, BorderLayout.CENTER);

        add(topBar, BorderLayout.NORTH);

        // ── Center Workspace: SplitPane with Filter Sidebar & Results Workspace ──
        filterPanel = new ConvertFilterPanel(predicate -> {
            tableModel.setFilter(predicate);
            updateFilterMetrics();
        });

        tableModel.addTableModelListener(e -> updateFilterMetrics());

        sidebarContainer.setPreferredSize(new Dimension(380, 500));
        sidebarContainer.setMinimumSize(new Dimension(58, 200));
        sidebarContainer.add(filterPanel, BorderLayout.CENTER);

        JPanel sidebarHeader = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 2));
        toggleSidebarBtn.setToolTipText("Toggle filter sidebar");
        toggleSidebarBtn.addActionListener(e -> toggleSidebar());
        sidebarHeader.add(toggleSidebarBtn);
        sidebarContainer.add(sidebarHeader, BorderLayout.NORTH);

        // ── Results Panel (Table + Editors) ──
        setupResultsTable();

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);

        editorTabs.addTab("\uD83D\uDCE4 Converted GET Request", convertedGetRequestEditor.uiComponent());
        editorTabs.addTab("\uD83D\uDCE5 GET Response", convertedGetResponseEditor.uiComponent());
        editorTabs.addTab("\uD83D\uDCE4 Original POST Request", originalPostRequestEditor.uiComponent());
        editorTabs.addTab("\uD83D\uDCE5 POST Response", originalPostResponseEditor.uiComponent());

        evidenceTextArea.setEditable(false);
        evidenceTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        editorTabs.addTab("\uD83D\uDD0D Analysis & Evidence", new JScrollPane(evidenceTextArea));

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, editorTabs);
        verticalSplit.setResizeWeight(0.48);

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sidebarContainer, verticalSplit);
        horizontalSplit.setResizeWeight(0.24);

        add(horizontalSplit, BorderLayout.CENTER);

        setupListeners();
    }

    public void setCompletionGlyphCallback(Consumer<Integer> callback) {
        this.completionGlyphCallback = callback;
    }

    private void updateFilterMetrics() {
        int total = tableModel.getAllResultsCount();
        int displayed = tableModel.getRowCount();
        int pinned = tableModel.getPinnedCount();
        filterPanel.updateMetrics(total, displayed, pinned);
    }

    private void toggleSidebar() {
        sidebarVisible = !sidebarVisible;
        if (sidebarVisible) {
            sidebarContainer.setPreferredSize(new Dimension(380, 500));
            filterPanel.setVisible(true);
            toggleSidebarBtn.setText("\u25c0 Filters");
        } else {
            sidebarContainer.setPreferredSize(new Dimension(58, 500));
            filterPanel.setVisible(false);
            toggleSidebarBtn.setText("\u25b6");
        }
        sidebarContainer.revalidate();
    }

    private void setupResultsTable() {
        resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        resultsTable.setAutoCreateRowSorter(true);

        resultsTable.getColumnModel().getColumn(0).setMaxWidth(45); // #
        resultsTable.getColumnModel().getColumn(1).setMaxWidth(60); // Method
        resultsTable.getColumnModel().getColumn(4).setMaxWidth(80); // POST Status
        resultsTable.getColumnModel().getColumn(5).setMaxWidth(80); // GET Status
        resultsTable.getColumnModel().getColumn(6).setMaxWidth(75); // POST Len
        resultsTable.getColumnModel().getColumn(7).setMaxWidth(75); // GET Len
        resultsTable.getColumnModel().getColumn(10).setMaxWidth(75); // Severity

        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                int modelRow = table.convertRowIndexToModel(row);
                ConversionResult res = tableModel.getResultAt(modelRow);

                if (res != null && !isSelected) {
                    if (tableModel.isPinned(res.id())) {
                        c.setBackground(new Color(255, 250, 205)); // Pinned row
                    } else if ("High".equalsIgnoreCase(res.severity())) {
                        c.setBackground(new Color(255, 230, 230));
                        c.setForeground(new Color(180, 0, 0));
                    } else if ("Medium".equalsIgnoreCase(res.severity())) {
                        c.setBackground(new Color(255, 246, 220));
                        c.setForeground(new Color(160, 90, 0));
                    } else if ("Low".equalsIgnoreCase(res.severity())) {
                        c.setBackground(new Color(240, 248, 255));
                        c.setForeground(new Color(0, 70, 140));
                    } else {
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                    }
                }
                return c;
            }
        });

        // ── Deep-Linking Quad on Selection ──
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
                    ConversionResult res = tableModel.getResultAt(modelRow);
                    if (res != null) {
                        applyDeepLinkingNavigation(res);
                    }
                }
            }
        });

        // ── Right-Click Context Menu (Burp Interoperability) ──
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem sendGetRepeater = new JMenuItem("Send Converted GET to Repeater");
        sendGetRepeater.addActionListener(e -> sendSelectedGetToRepeater());

        JMenuItem sendPostRepeater = new JMenuItem("Send Original POST to Repeater");
        sendPostRepeater.addActionListener(e -> sendSelectedPostToRepeater());

        JMenuItem sendGetIntruder = new JMenuItem("Send Converted GET to Intruder");
        sendGetIntruder.addActionListener(e -> sendSelectedGetIntruder());

        JMenuItem sendOrganizer = new JMenuItem("Send Converted Result to Organizer");
        sendOrganizer.addActionListener(e -> sendSelectedToOrganizer());

        JMenuItem pinItem = new JMenuItem("Pin Selected Result(s)");
        pinItem.addActionListener(e -> pinSelectedRows());

        JMenuItem clearPinsItem = new JMenuItem("Clear Pins");
        clearPinsItem.addActionListener(e -> {
            tableModel.clearPins();
            updateFilterMetrics();
        });

        JMenuItem exportAllItem = new JMenuItem("Export All Visible Results to TSV...");
        JMenuItem exportSelectedItem = new JMenuItem("Export Selected Result(s) to TSV...");
        JMenuItem copyTsvItem = new JMenuItem("Copy Selected Row as TSV");

        exportAllItem.addActionListener(e -> exportResultsToTsv(false));
        exportSelectedItem.addActionListener(e -> exportResultsToTsv(true));
        copyTsvItem.addActionListener(e -> copySelectedRowAsTsv());

        popupMenu.add(sendGetRepeater);
        popupMenu.add(sendPostRepeater);
        popupMenu.add(sendGetIntruder);
        popupMenu.add(sendOrganizer);
        popupMenu.addSeparator();
        popupMenu.add(pinItem);
        popupMenu.add(clearPinsItem);
        popupMenu.addSeparator();
        popupMenu.add(exportAllItem);
        popupMenu.add(exportSelectedItem);
        popupMenu.addSeparator();
        popupMenu.add(copyTsvItem);

        resultsTable.setComponentPopupMenu(popupMenu);

        // ── Keyboard Shortcut: Copy row as TSV ──
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        resultsTable.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copyTsv");
        resultsTable.getActionMap().put("copyTsv", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedRowAsTsv();
            }
        });
    }

    /**
     * Implements the 4-Pillar Deep-Linking Architecture from extension_architecture.md.
     */
    private void applyDeepLinkingNavigation(ConversionResult res) {
        HttpRequest getReq = res.convertedGetRequest();
        HttpResponse getResp = res.convertedGetResponse();
        HttpRequest postReq = res.originalPostRequest();
        HttpResponse postResp = res.originalPostResponse();

        String queryParam = res.path().contains("?") ? res.path().substring(res.path().indexOf("?") + 1) : "";

        // Pillar 1: Auto-Switch Tab
        if ("High".equalsIgnoreCase(res.severity()) || "Medium".equalsIgnoreCase(res.severity())) {
            editorTabs.setSelectedIndex(1); // GET Response
        } else {
            editorTabs.setSelectedIndex(0); // Converted GET Request
        }

        // Pillar 2: Native Marker Highlighting
        if (getReq != null) {
            HttpRequest reqToDisplay = getReq;
            if (!queryParam.isEmpty()) {
                String reqStr = getReq.toString();
                int start = reqStr.indexOf(queryParam);
                if (start >= 0) {
                    reqToDisplay = reqToDisplay.withMarkers(Marker.marker(Range.range(start, start + queryParam.length())));
                }
            }
            convertedGetRequestEditor.setRequest(reqToDisplay);
        }

        if (getResp != null) {
            convertedGetResponseEditor.setResponse(getResp);
        }

        if (postReq != null) originalPostRequestEditor.setRequest(postReq);
        if (postResp != null) originalPostResponseEditor.setResponse(postResp);

        // Pillar 3: Populate native editor search bar
        if (!queryParam.isEmpty()) {
            convertedGetRequestEditor.setSearchExpression(queryParam);
        }

        // Pillar 4: Auto-scroll viewport via Caret / Search
        if (!queryParam.isEmpty() && getReq != null) {
            String reqStr = getReq.toString();
            int start = reqStr.indexOf(queryParam);
            if (start >= 0) {
                final int caret = start;
                SwingUtilities.invokeLater(() -> {
                    try {
                        java.lang.reflect.Method m = convertedGetRequestEditor.getClass().getMethod("setCaretPosition", int.class);
                        m.invoke(convertedGetRequestEditor, caret);
                    } catch (Exception ignored) {}
                });
            }
        }

        // Populate Evidence pane
        StringBuilder ev = new StringBuilder();
        ev.append("=== POST TO GET CONVERSION ANALYSIS ===\n\n");
        ev.append("Target URL:       ").append(res.url()).append("\n");
        ev.append("POST Baseline:    HTTP ").append(res.baseStatus()).append(" (").append(res.baseLength()).append(" bytes)\n");
        ev.append("Converted GET:    HTTP ").append(res.getStatus()).append(" (").append(res.getLength()).append(" bytes)\n");
        ev.append("Signal:           ").append(res.signal()).append("\n");
        ev.append("Severity:         ").append(res.severity()).append("\n\n");
        ev.append("Evidence Details:\n").append(res.evidence()).append("\n\n");
        ev.append("Timestamp:        ").append(res.timestamp()).append("\n");
        evidenceTextArea.setText(ev.toString());
    }

    private void pinSelectedRows() {
        int[] rows = resultsTable.getSelectedRows();
        for (int r : rows) {
            int modelRow = resultsTable.convertRowIndexToModel(r);
            ConversionResult res = tableModel.getResultAt(modelRow);
            if (res != null) {
                tableModel.pin(res.id());
            }
        }
        updateFilterMetrics();
    }

    private void sendSelectedGetToRepeater() {
        int[] rows = resultsTable.getSelectedRows();
        for (int r : rows) {
            int modelRow = resultsTable.convertRowIndexToModel(r);
            ConversionResult res = tableModel.getResultAt(modelRow);
            if (res != null && res.convertedGetRequest() != null) {
                String tabName = "GET " + res.host() + res.path();
                api.repeater().sendToRepeater(res.convertedGetRequest(), tabName);
            }
        }
        statusLabel.setText("Sent " + rows.length + " GET request(s) to Repeater.");
    }

    private void sendSelectedPostToRepeater() {
        int[] rows = resultsTable.getSelectedRows();
        for (int r : rows) {
            int modelRow = resultsTable.convertRowIndexToModel(r);
            ConversionResult res = tableModel.getResultAt(modelRow);
            if (res != null && res.originalPostRequest() != null) {
                String tabName = "POST " + res.host() + res.path();
                api.repeater().sendToRepeater(res.originalPostRequest(), tabName);
            }
        }
        statusLabel.setText("Sent " + rows.length + " POST request(s) to Repeater.");
    }

    private void sendSelectedGetIntruder() {
        int[] rows = resultsTable.getSelectedRows();
        for (int r : rows) {
            int modelRow = resultsTable.convertRowIndexToModel(r);
            ConversionResult res = tableModel.getResultAt(modelRow);
            if (res != null && res.convertedGetRequest() != null) {
                api.intruder().sendToIntruder(res.convertedGetRequest());
            }
        }
        statusLabel.setText("Sent " + rows.length + " GET request(s) to Intruder.");
    }

    private void sendSelectedToOrganizer() {
        int[] rows = resultsTable.getSelectedRows();
        int count = 0;
        for (int r : rows) {
            int modelRow = resultsTable.convertRowIndexToModel(r);
            ConversionResult res = tableModel.getResultAt(modelRow);
            if (res != null && res.convertedRequestResponse() != null) {
                api.organizer().sendToOrganizer(res.convertedRequestResponse());
                count++;
            }
        }
        statusLabel.setText("Sent " + count + " result(s) to Organizer.");
    }

    private void copySelectedRowAsTsv() {
        int[] rows = resultsTable.getSelectedRows();
        if (rows.length == 0) return;
        StringBuilder sb = new StringBuilder();
        for (int r : rows) {
            int modelRow = resultsTable.convertRowIndexToModel(r);
            ConversionResult res = tableModel.getResultAt(modelRow);
            if (res != null) {
                sb.append(String.join("\t",
                    String.valueOf(res.id()),
                    sanitizeTsv(res.method()),
                    sanitizeTsv(res.url()),
                    sanitizeTsv(res.path()),
                    String.valueOf(res.baseStatus()),
                    String.valueOf(res.getStatus()),
                    String.valueOf(res.baseLength()),
                    String.valueOf(res.getLength()),
                    sanitizeTsv(res.getContentType()),
                    sanitizeTsv(res.signal()),
                    sanitizeTsv(res.severity())
                )).append("\n");
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString().trim()), null);
        statusLabel.setText("Copied " + rows.length + " result(s) to clipboard as TSV.");
    }

    private void exportResultsToTsv(boolean selectedOnly) {
        List<ConversionResult> resultsToExport;
        if (selectedOnly) {
            int[] selectedRows = resultsTable.getSelectedRows();
            if (selectedRows.length == 0) {
                JOptionPane.showMessageDialog(this, "No rows selected to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            resultsToExport = new ArrayList<>();
            for (int row : selectedRows) {
                int modelRow = resultsTable.convertRowIndexToModel(row);
                ConversionResult res = tableModel.getResultAt(modelRow);
                if (res != null) {
                    resultsToExport.add(res);
                }
            }
        } else {
            resultsToExport = tableModel.getFilteredResults();
            if (resultsToExport.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No results available to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Conversion Results to TSV");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Tab-Separated Values (*.tsv)", "tsv"));
        String defaultFileName = "ConvertPostToGet_Results_" + System.currentTimeMillis() + ".tsv";
        fileChooser.setSelectedFile(new java.io.File(defaultFileName));

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().toLowerCase().endsWith(".tsv")) {
                fileToSave = new java.io.File(fileToSave.getParentFile(), fileToSave.getName() + ".tsv");
            }

            try (java.io.BufferedWriter writer = new java.io.BufferedWriter(new java.io.FileWriter(fileToSave, java.nio.charset.StandardCharsets.UTF_8))) {
                writer.write(String.join("\t",
                    "ID", "Method", "URL", "Path", "POST Status", "GET Status",
                    "POST Length", "GET Length", "Content-Type", "Signal", "Severity", "Evidence", "Timestamp"
                ));
                writer.newLine();

                for (ConversionResult res : resultsToExport) {
                    String line = String.join("\t",
                        String.valueOf(res.id()),
                        sanitizeTsv(res.method()),
                        sanitizeTsv(res.url()),
                        sanitizeTsv(res.path()),
                        String.valueOf(res.baseStatus()),
                        String.valueOf(res.getStatus()),
                        String.valueOf(res.baseLength()),
                        String.valueOf(res.getLength()),
                        sanitizeTsv(res.getContentType()),
                        sanitizeTsv(res.signal()),
                        sanitizeTsv(res.severity()),
                        sanitizeTsv(res.evidence()),
                        sanitizeTsv(res.timestamp() != null ? res.timestamp().toString() : "")
                    );
                    writer.write(line);
                    writer.newLine();
                }

                statusLabel.setText("Exported " + resultsToExport.size() + " result(s) to " + fileToSave.getName());
                JOptionPane.showMessageDialog(
                    this,
                    "Successfully exported " + resultsToExport.size() + " result(s) to:\n" + fileToSave.getAbsolutePath(),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE
                );
            } catch (Exception ex) {
                api.logging().logToError("Failed to export TSV: " + ex.getMessage());
                JOptionPane.showMessageDialog(
                    this,
                    "Failed to export TSV:\n" + ex.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    private static String sanitizeTsv(String val) {
        if (val == null) return "";
        return val.replace("\t", " ").replace("\r\n", " ").replace("\n", " ").replace("\r", " ");
    }

    private void setupListeners() {
        AtomicInteger findingsCounter = new AtomicInteger(0);

        startButton.addActionListener(e -> {
            startButton.setEnabled(false);
            pauseButton.setEnabled(true);
            stopButton.setEnabled(true);
            filterPanel.resetSmartSignatures();
            findingsCounter.set(0);

            engine.runConversionBatch(
                targetCandidates,
                sessionHeaders,
                result -> SwingUtilities.invokeLater(() -> {
                    tableModel.addResult(result);
                    if ("High".equalsIgnoreCase(result.severity()) || "Medium".equalsIgnoreCase(result.severity())) {
                        findingsCounter.incrementAndGet();
                    }
                }),
                status -> SwingUtilities.invokeLater(() -> statusLabel.setText(status)),
                () -> SwingUtilities.invokeLater(() -> {
                    startButton.setEnabled(true);
                    pauseButton.setEnabled(false);
                    pauseButton.setText("Pause");
                    stopButton.setEnabled(false);

                    // Fire live status glyph callback on completion
                    if (completionGlyphCallback != null) {
                        completionGlyphCallback.accept(findingsCounter.get());
                    }
                })
            );
        });

        pauseButton.addActionListener(e -> {
            if (engine.getPauseController().isPaused()) {
                engine.getPauseController().resume();
                pauseButton.setText("Pause");
                statusLabel.setText("Resumed conversions...");
            } else {
                engine.getPauseController().pause();
                pauseButton.setText("Resume");
                statusLabel.setText("Paused.");
            }
        });

        stopButton.addActionListener(e -> {
            engine.stop();
            startButton.setEnabled(true);
            pauseButton.setEnabled(false);
            pauseButton.setText("Pause");
            stopButton.setEnabled(false);
            statusLabel.setText("Stopped by user.");
        });

        pinSelectedBtn.addActionListener(e -> pinSelectedRows());
        clearPinsBtn.addActionListener(e -> {
            tableModel.clearPins();
            updateFilterMetrics();
        });

        customHeadersButton.addActionListener(e -> {
            Frame frame = (Frame) SwingUtilities.getWindowAncestor(this);
            CustomHeadersDialog dialog = new CustomHeadersDialog(frame, sessionHeaders, updated -> {
                sessionHeaders.clear();
                sessionHeaders.addAll(updated);
                customHeadersButton.setText("Custom Headers & Auth... (" + sessionHeaders.size() + ")");
                statusLabel.setText("Applied " + sessionHeaders.size() + " custom header(s) / auth tokens.");
            });
            dialog.setVisible(true);
        });

        exportTsvButton.addActionListener(e -> exportResultsToTsv(false));

        clearButton.addActionListener(e -> {
            tableModel.clear();
            filterPanel.resetSmartSignatures();
            updateFilterMetrics();
            statusLabel.setText("Results cleared.");
        });

        optionsButton.addActionListener(e -> {
            Frame frame = (Frame) SwingUtilities.getWindowAncestor(this);
            ConvertOptionsDialog dialog = new ConvertOptionsDialog(frame, config);
            dialog.setVisible(true);
        });
    }

    public void cleanup() {
        engine.stop();
    }
}
