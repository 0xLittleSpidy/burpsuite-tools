package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.engine.PostToGetEngine;
import com.littlespidy.convertposttoget.model.ConfiguredHeader;
import com.littlespidy.convertposttoget.model.ConversionResult;
import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import com.littlespidy.convertposttoget.model.PostCandidate;
import burp.api.montoya.MontoyaApi;
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
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated Conversion Session Panel with live results table, collapsible filter sidebar,
 * Montoya comparative request/response editors, and custom headers/auth token injection.
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
    private final JButton toggleSidebarBtn = new JButton("◀");
    private boolean sidebarVisible = true;

    private final JButton startButton = new JButton("Start Conversion Test");
    private final JButton pauseButton = new JButton("Pause");
    private final JButton stopButton = new JButton("Stop");
    private final JButton customHeadersButton = new JButton("Custom Headers & Auth... (0)");
    private final JButton exportTsvButton = new JButton("Export TSV...");
    private final JButton clearButton = new JButton("Clear Results");
    private final JButton optionsButton = new JButton("Options...");
    private final JLabel statusLabel = new JLabel("Ready.");

    private final List<ConfiguredHeader> sessionHeaders = new ArrayList<>();

    private final HttpRequestEditor convertedGetRequestEditor;
    private final HttpResponseEditor convertedGetResponseEditor;
    private final HttpRequestEditor originalPostRequestEditor;
    private final HttpResponseEditor originalPostResponseEditor;
    private final JTextArea evidenceTextArea = new JTextArea();

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

        // ── Montoya Editors ──
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

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttonPanel.add(startButton);
        buttonPanel.add(pauseButton);
        buttonPanel.add(stopButton);
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

        // ── Center Workspace: SplitPane with Filter Sidebar & Results Panel ──
        filterPanel = new ConvertFilterPanel(tableModel::setFilter);
        sidebarContainer.setPreferredSize(new Dimension(280, 500));
        sidebarContainer.add(filterPanel, BorderLayout.CENTER);

        JPanel sidebarHeader = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 2));
        toggleSidebarBtn.setToolTipText("Collapse filter sidebar");
        toggleSidebarBtn.addActionListener(e -> toggleSidebar());
        sidebarHeader.add(toggleSidebarBtn);
        sidebarContainer.add(sidebarHeader, BorderLayout.NORTH);

        // ── Results Panel (Table + Editors) ──
        setupResultsTable();

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);

        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Converted GET Request", convertedGetRequestEditor.uiComponent());
        editorTabs.addTab("GET Response", convertedGetResponseEditor.uiComponent());
        editorTabs.addTab("Original POST Request", originalPostRequestEditor.uiComponent());
        editorTabs.addTab("POST Response", originalPostResponseEditor.uiComponent());

        evidenceTextArea.setEditable(false);
        evidenceTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        editorTabs.addTab("Analysis & Evidence", new JScrollPane(evidenceTextArea));

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, editorTabs);
        verticalSplit.setResizeWeight(0.48);

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sidebarContainer, verticalSplit);
        horizontalSplit.setResizeWeight(0.2);

        add(horizontalSplit, BorderLayout.CENTER);

        // ── Wire Action Listeners ──
        setupListeners();
    }

    private void toggleSidebar() {
        sidebarVisible = !sidebarVisible;
        if (sidebarVisible) {
            sidebarContainer.setPreferredSize(new Dimension(280, 500));
            filterPanel.setVisible(true);
            toggleSidebarBtn.setText("◀");
        } else {
            sidebarContainer.setPreferredSize(new Dimension(38, 500));
            filterPanel.setVisible(false);
            toggleSidebarBtn.setText("▶");
        }
        sidebarContainer.revalidate();
    }

    private void setupResultsTable() {
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setAutoCreateRowSorter(true);

        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                int modelRow = table.convertRowIndexToModel(row);
                ConversionResult res = tableModel.getResultAt(modelRow);

                if (res != null && !isSelected) {
                    if ("High".equalsIgnoreCase(res.severity())) {
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

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
                    ConversionResult res = tableModel.getResultAt(modelRow);
                    if (res != null) {
                        if (res.convertedGetRequest() != null) convertedGetRequestEditor.setRequest(res.convertedGetRequest());
                        if (res.convertedGetResponse() != null) convertedGetResponseEditor.setResponse(res.convertedGetResponse());
                        if (res.originalPostRequest() != null) originalPostRequestEditor.setRequest(res.originalPostRequest());
                        if (res.originalPostResponse() != null) originalPostResponseEditor.setResponse(res.originalPostResponse());

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
                }
            }
        });

        // ── Right-Click Context Menu ──
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem exportAllItem = new JMenuItem("Export All Visible Results to TSV...");
        JMenuItem exportSelectedItem = new JMenuItem("Export Selected Result(s) to TSV...");
        JMenuItem copyTsvItem = new JMenuItem("Copy Selected Row as TSV");

        exportAllItem.addActionListener(e -> exportResultsToTsv(false));
        exportSelectedItem.addActionListener(e -> exportResultsToTsv(true));
        copyTsvItem.addActionListener(e -> copySelectedRowAsTsv());

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

    private void copySelectedRowAsTsv() {
        int row = resultsTable.getSelectedRow();
        if (row >= 0) {
            int modelRow = resultsTable.convertRowIndexToModel(row);
            ConversionResult res = tableModel.getResultAt(modelRow);
            if (res != null) {
                String tsv = String.join("\t",
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
                );
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(tsv), null);
                statusLabel.setText("Copied result #" + res.id() + " to clipboard as TSV.");
            }
        }
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
        startButton.addActionListener(e -> {
            startButton.setEnabled(false);
            pauseButton.setEnabled(true);
            stopButton.setEnabled(true);
            filterPanel.resetSmartSignatures();

            engine.runConversionBatch(
                targetCandidates,
                sessionHeaders,
                result -> SwingUtilities.invokeLater(() -> tableModel.addResult(result)),
                status -> SwingUtilities.invokeLater(() -> statusLabel.setText(status)),
                () -> SwingUtilities.invokeLater(() -> {
                    startButton.setEnabled(true);
                    pauseButton.setEnabled(false);
                    pauseButton.setText("Pause");
                    stopButton.setEnabled(false);
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
