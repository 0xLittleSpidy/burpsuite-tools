// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.engine.ProbeProgressListener_littlespidy;
import com.littlespidy.apiinspector.engine.VersionProbeEngine_littlespidy;
import com.littlespidy.apiinspector.model.APIVersionPresets_littlespidy;
import com.littlespidy.apiinspector.model.ProbeResult_littlespidy;
import com.littlespidy.apiinspector.model.SessionStore_littlespidy;
import com.littlespidy.apiinspector.strategy.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Dedicated session panel for an individual API request.
 * Contains baseline summary, strategy configuration, candidate wordlist,
 * sortable probe results table, and Burp request/response editors.
 */
public class RequestSessionPanel_littlespidy extends JPanel implements ProbeProgressListener_littlespidy {

    private final MontoyaApi api;
    private final VersionProbeEngine_littlespidy engine;
    private HttpRequest baselineRequest;
    private HttpResponse baselineResponse;
    private SessionStore_littlespidy sessionStore;

    // UI Elements
    private JLabel targetLabel;
    private JLabel baselineStatusLabel;
    private JLabel progressLabel;
    private JProgressBar progressBar;

    private JCheckBox uriPathCheck;
    private JCheckBox headerCheck;
    private JCheckBox queryParamCheck;
    private JCheckBox contentNegCheck;
    private JCheckBox subdomainCheck;
    private JCheckBox cookieCheck;

    private JComboBox<String> presetCombo;
    private JLabel candidateCountLabel;
    private JTextField candidateInput;
    private JSpinner threadSpinner;
    private JSpinner delaySpinner;

    private JButton startButton;
    private JButton stopButton;
    private JButton clearButton;
    private JButton exportButton;

    private JTable resultsTable;
    private VersionResultsTableModel_littlespidy tableModel;
    private TableRowSorter<VersionResultsTableModel_littlespidy> tableSorter;

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JTextArea diffDetailsArea;

    public RequestSessionPanel_littlespidy(MontoyaApi api, HttpRequest baselineRequest, HttpResponse baselineResponse) {
        super(new BorderLayout(5, 5));
        this.api = api;
        this.baselineRequest = baselineRequest;
        this.baselineResponse = baselineResponse;
        this.engine = new VersionProbeEngine_littlespidy(api != null ? api.http() : null);

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
        updateBaselineDisplay();
    }

    private void initComponents() {
        // --- 1. Top Panel: Baseline Info & Configuration ---
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        // Baseline Summary Card
        JPanel baselineCard = new JPanel(new BorderLayout(5, 5));
        baselineCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Target Baseline Endpoint", TitledBorder.LEFT, TitledBorder.TOP));

        targetLabel = new JLabel("Target: Loading...");
        targetLabel.setFont(targetLabel.getFont().deriveFont(Font.BOLD));
        baselineStatusLabel = new JLabel("Status: Unknown");

        JPanel baselineInfoBox = new JPanel(new GridLayout(2, 1, 4, 4));
        baselineInfoBox.setBorder(new EmptyBorder(4, 6, 4, 6));
        baselineInfoBox.add(targetLabel);
        baselineInfoBox.add(baselineStatusLabel);
        baselineCard.add(baselineInfoBox, BorderLayout.CENTER);

        JButton fetchBaselineBtn = new JButton("Fetch / Refresh Baseline");
        fetchBaselineBtn.setToolTipText("Sends the baseline request to verify its current live status and response length");
        fetchBaselineBtn.addActionListener(e -> fetchBaseline());
        baselineCard.add(fetchBaselineBtn, BorderLayout.EAST);

        topContainer.add(baselineCard);
        topContainer.add(Box.createVerticalStrut(6));

        // Strategy & Execution Controls Card
        JPanel configCard = new JPanel(new BorderLayout(6, 6));
        configCard.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Probing Strategies & Configuration", TitledBorder.LEFT, TitledBorder.TOP));

        // Strategies Checkboxes
        JPanel strategiesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        uriPathCheck = new JCheckBox("URI Path", true);
        headerCheck = new JCheckBox("Headers", true);
        queryParamCheck = new JCheckBox("Query Params", true);
        contentNegCheck = new JCheckBox("Content Negotiation (Accept)", true);
        subdomainCheck = new JCheckBox("Subdomains", false);
        cookieCheck = new JCheckBox("Cookies", false);

        strategiesPanel.add(new JLabel("Active Strategies:"));
        strategiesPanel.add(uriPathCheck);
        strategiesPanel.add(headerCheck);
        strategiesPanel.add(queryParamCheck);
        strategiesPanel.add(contentNegCheck);
        strategiesPanel.add(subdomainCheck);
        strategiesPanel.add(cookieCheck);

        // Candidate Versions Row with Presets & Count
        JPanel candidatesPanel = new JPanel(new BorderLayout(6, 2));
        candidatesPanel.setBorder(new EmptyBorder(2, 6, 2, 6));

        JPanel candLeftBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        candLeftBox.add(new JLabel("Preset:"));
        presetCombo = new JComboBox<>(new String[]{
                "Extended (1,091 Versions: v0 to v10.99)",
                "Common Standard (13 Versions)",
                "Major Numeric (11 Versions: v0 to v10)",
                "Custom"
        });
        candLeftBox.add(presetCombo);

        candidateCountLabel = new JLabel("[1,091 Candidates]");
        candidateCountLabel.setFont(candidateCountLabel.getFont().deriveFont(Font.BOLD, 11f));
        candLeftBox.add(candidateCountLabel);
        candLeftBox.add(new JLabel("Candidates:"));
        candidatesPanel.add(candLeftBox, BorderLayout.WEST);

        candidateInput = new JTextField(APIVersionPresets_littlespidy.getExtendedVersionsCommaSeparated());
        candidateInput.setToolTipText("Comma, newline, or space-separated list of candidate version values to test");
        candidatesPanel.add(candidateInput, BorderLayout.CENTER);

        presetCombo.addActionListener(e -> {
            int idx = presetCombo.getSelectedIndex();
            if (idx == 0) {
                candidateInput.setText(APIVersionPresets_littlespidy.getExtendedVersionsCommaSeparated());
            } else if (idx == 1) {
                candidateInput.setText(APIVersionPresets_littlespidy.getCommonVersionsCommaSeparated());
            } else if (idx == 2) {
                candidateInput.setText(APIVersionPresets_littlespidy.getMajorVersionsCommaSeparated());
            }
            updateCandidateCountDisplay();
        });

        candidateInput.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { updateCandidateCountDisplay(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { updateCandidateCountDisplay(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { updateCandidateCountDisplay(); }
        });

        // Action Toolbar: Concurrency, Delay, Start, Stop, Clear, Export
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        actionPanel.add(new JLabel("Threads:"));
        threadSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 20, 1));
        actionPanel.add(threadSpinner);

        actionPanel.add(new JLabel("Delay (ms):"));
        delaySpinner = new JSpinner(new SpinnerNumberModel(0, 0, 5000, 50));
        actionPanel.add(delaySpinner);

        startButton = new JButton("Start Probing");
        startButton.setFont(startButton.getFont().deriveFont(Font.BOLD));
        startButton.addActionListener(e -> startProbing());
        actionPanel.add(startButton);

        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopProbing());
        actionPanel.add(stopButton);

        clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        actionPanel.add(clearButton);

        exportButton = new JButton("Export CSV");
        exportButton.addActionListener(e -> exportCsv());
        actionPanel.add(exportButton);

        progressLabel = new JLabel("Ready");
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(160, 20));
        progressBar.setVisible(false);

        actionPanel.add(Box.createHorizontalStrut(10));
        actionPanel.add(progressBar);
        actionPanel.add(progressLabel);

        JPanel configCenter = new JPanel();
        configCenter.setLayout(new BoxLayout(configCenter, BoxLayout.Y_AXIS));
        configCenter.add(strategiesPanel);
        configCenter.add(candidatesPanel);
        configCenter.add(actionPanel);
        configCard.add(configCenter, BorderLayout.CENTER);

        topContainer.add(configCard);
        add(topContainer, BorderLayout.NORTH);

        // --- 2. Center Panel: Split Pane (Results Table on top, Request/Response on bottom) ---
        tableModel = new VersionResultsTableModel_littlespidy();
        resultsTable = new JTable(tableModel);
        tableSorter = new TableRowSorter<>(tableModel);
        tableSorter.setSortsOnUpdates(true);
        resultsTable.setRowSorter(tableSorter);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        // Selection Listener to update viewer
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onTableRowSelected();
            }
        });

        // Context Menu on Results Table
        setupTableContextMenu();

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        tableScrollPane.setPreferredSize(new Dimension(800, 240));

        // Bottom Inspection Area: Request, Response, and Diff Summary
        JPanel bottomInspectionPanel = new JPanel(new BorderLayout());
        JTabbedPane viewerTabs = new JTabbedPane();

        Component reqComp;
        Component respComp;
        if (api != null && api.userInterface() != null) {
            UserInterface ui = api.userInterface();
            requestEditor = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseEditor = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);
            reqComp = requestEditor.uiComponent();
            respComp = responseEditor.uiComponent();
        } else {
            reqComp = new JScrollPane(new JTextArea("Burp UI not connected (standalone / test mode)."));
            respComp = new JScrollPane(new JTextArea("Burp UI not connected (standalone / test mode)."));
        }

        viewerTabs.addTab("Request", reqComp);
        viewerTabs.addTab("Response", respComp);

        diffDetailsArea = new JTextArea();
        diffDetailsArea.setEditable(false);
        diffDetailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        diffDetailsArea.setText("Select a result above to inspect details and diff comparison.");
        viewerTabs.addTab("Diff Comparison", new JScrollPane(diffDetailsArea));

        bottomInspectionPanel.add(viewerTabs, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, bottomInspectionPanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(260);

        add(splitPane, BorderLayout.CENTER);
    }

    public void setSessionStore(SessionStore_littlespidy sessionStore) {
        this.sessionStore = sessionStore;
    }

    public SessionStore_littlespidy getSessionStore() {
        return sessionStore;
    }

    private void updateBaselineDisplay() {
        if (baselineRequest == null) {
            targetLabel.setText("Target: No baseline request loaded");
            baselineStatusLabel.setText("Status: N/A");
            return;
        }

        String method = baselineRequest.method();
        String url = baselineRequest.url();
        targetLabel.setText("Target: [" + (method != null ? method : "GET") + "] " + (url != null ? url : "/"));

        if (baselineResponse != null) {
            int code = baselineResponse.statusCode();
            int len = baselineResponse.body() != null ? baselineResponse.body().length() : 0;
            String mime = baselineResponse.mimeType() != null ? baselineResponse.mimeType().name() : "-";
            baselineStatusLabel.setText("Baseline Status: " + code + " | Length: " + len + " bytes | MIME: " + mime);
        } else {
            baselineStatusLabel.setText("Baseline Status: Response not fetched yet");
        }
    }

    private void fetchBaseline() {
        if (baselineRequest == null || api == null) return;
        progressLabel.setText("Fetching baseline...");
        new Thread(() -> {
            try {
                HttpRequest req = (sessionStore != null && sessionStore.isEnabled()) ? sessionStore.applyToRequest(baselineRequest) : baselineRequest;
                HttpRequestResponse resp = api.http().sendRequest(req);
                if (resp != null && resp.hasResponse()) {
                    baselineResponse = resp.response();
                    SwingUtilities.invokeLater(() -> {
                        updateBaselineDisplay();
                        progressLabel.setText("Baseline updated.");
                        if (onStateChangedCallback != null) {
                            onStateChangedCallback.run();
                        }
                    });
                }
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> progressLabel.setText("Failed to fetch baseline: " + ex.getMessage()));
            }
        }).start();
    }

    private void startProbing() {
        if (baselineRequest == null) {
            JOptionPane.showMessageDialog(this, "No baseline request available to probe.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        List<VersionStrategy_littlespidy> active = new ArrayList<>();
        if (uriPathCheck.isSelected()) active.add(new UriPathStrategy_littlespidy());
        if (headerCheck.isSelected()) active.add(new HeaderStrategy_littlespidy());
        if (queryParamCheck.isSelected()) active.add(new QueryParamStrategy_littlespidy());
        if (contentNegCheck.isSelected()) active.add(new ContentNegotiationStrategy_littlespidy());
        if (subdomainCheck.isSelected()) active.add(new SubdomainStrategy_littlespidy());
        if (cookieCheck.isSelected()) active.add(new CookieStrategy_littlespidy());

        if (active.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select at least one versioning strategy.", "Notice", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String rawCandidates = candidateInput.getText().trim();
        List<String> candidates = new ArrayList<>();
        if (!rawCandidates.isEmpty()) {
            for (String c : rawCandidates.split("[,\\r?\\n\\s]+")) {
                String clean = c.trim();
                if (!clean.isEmpty()) {
                    candidates.add(clean);
                }
            }
        }

        if (candidates.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please provide at least one version candidate.", "Notice", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int threads = (Integer) threadSpinner.getValue();
        int delay = (Integer) delaySpinner.getValue();

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        progressBar.setValue(0);
        progressBar.setVisible(true);

        engine.startProbing(baselineRequest, baselineResponse, active, candidates, threads, delay, sessionStore, this);
    }

    private void stopProbing() {
        engine.stopProbing();
        progressLabel.setText("Stopping probing...");
    }

    private void clearResults() {
        tableModel.clear();
        diffDetailsArea.setText("Select a result above to inspect details and diff comparison.");
        progressLabel.setText("Results cleared.");
        if (onStateChangedCallback != null) {
            onStateChangedCallback.run();
        }
    }

    private void exportCsv() {
        List<ProbeResult_littlespidy> all = tableModel.getAllResults();
        if (all.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No results to export.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("api_inspector_results.csv"));
        int ret = fileChooser.showSaveDialog(this);
        if (ret == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write("ID,Strategy,Variation,Status,Length,MIME,Diff Analysis,Latency (ms)\n");
                for (ProbeResult_littlespidy r : all) {
                    writer.write(String.format("%d,\"%s\",\"%s\",%d,%d,\"%s\",\"%s\",%d\n",
                            r.getId(),
                            escapeCsv(r.getStrategyName()),
                            escapeCsv(r.getVariation()),
                            r.getStatusCode(),
                            r.getResponseLength(),
                            escapeCsv(r.getMimeType()),
                            escapeCsv(r.getDiffAnalysis()),
                            r.getLatencyMs()
                    ));
                }
                JOptionPane.showMessageDialog(this, "Exported " + all.size() + " results to " + file.getName(), "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Failed to export CSV: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String escapeCsv(String val) {
        if (val == null) return "";
        return val.replace("\"", "\"\"");
    }

    private void onTableRowSelected() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow == -1) return;

        int modelRow = resultsTable.convertRowIndexToModel(viewRow);
        ProbeResult_littlespidy result = tableModel.getResultAt(modelRow);
        if (result == null) return;

        if (requestEditor != null && result.getRequest() != null) {
            requestEditor.setRequest(result.getRequest());
        }
        if (responseEditor != null) {
            if (result.getResponse() != null) {
                responseEditor.setResponse(result.getResponse());
            } else {
                responseEditor.setResponse(null);
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== PROBE RESULT #").append(result.getId()).append(" ===\n");
        sb.append("Strategy:    ").append(result.getStrategyName()).append("\n");
        sb.append("Variation:   ").append(result.getVariation()).append("\n");
        sb.append("Status:      ").append(result.getStatusCode()).append("\n");
        sb.append("Length:      ").append(result.getResponseLength()).append(" bytes\n");
        sb.append("MIME Type:   ").append(result.getMimeType()).append("\n");
        sb.append("Latency:     ").append(result.getLatencyMs()).append(" ms\n");
        sb.append("Diff State:  ").append(result.getDiffAnalysis()).append("\n\n");

        if (baselineResponse != null) {
            sb.append("=== BASELINE COMPARISON ===\n");
            sb.append("Baseline Status: ").append(baselineResponse.statusCode()).append("\n");
            int baseLen = baselineResponse.body() != null ? baselineResponse.body().length() : 0;
            sb.append("Baseline Length: ").append(baseLen).append(" bytes\n");
            int delta = result.getResponseLength() - baseLen;
            sb.append("Length Delta:    ").append(delta >= 0 ? "+" : "").append(delta).append(" bytes\n");
        } else {
            sb.append("Baseline response was not recorded.\n");
        }

        diffDetailsArea.setText(sb.toString());
        diffDetailsArea.setCaretPosition(0);
    }

    private void setupTableContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow != -1 && api != null && api.repeater() != null) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                ProbeResult_littlespidy r = tableModel.getResultAt(modelRow);
                if (r != null && r.getRequest() != null) {
                    api.repeater().sendToRepeater(r.getRequest(), "API vProbe #" + r.getId());
                }
            }
        });
        contextMenu.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        sendToIntruder.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow != -1 && api != null && api.intruder() != null) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                ProbeResult_littlespidy r = tableModel.getResultAt(modelRow);
                if (r != null && r.getRequest() != null) {
                    api.intruder().sendToIntruder(r.getRequest());
                }
            }
        });
        contextMenu.add(sendToIntruder);

        contextMenu.addSeparator();

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                ProbeResult_littlespidy r = tableModel.getResultAt(modelRow);
                if (r != null && r.getRequest() != null) {
                    String url = r.getRequest().url();
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url != null ? url : ""), null);
                }
            }
        });
        contextMenu.add(copyUrl);

        JMenuItem copyRequest = new JMenuItem("Copy Request");
        copyRequest.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow != -1) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                ProbeResult_littlespidy r = tableModel.getResultAt(modelRow);
                if (r != null && r.getRequest() != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(r.getRequest().toString()), null);
                }
            }
        });
        contextMenu.add(copyRequest);

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = resultsTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && row < resultsTable.getRowCount()) {
                        resultsTable.setRowSelectionInterval(row, row);
                    }
                    contextMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    // --- ProbeProgressListener callbacks ---
    @Override
    public void onProbeStarted(int totalRequests) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setMaximum(totalRequests);
            progressBar.setValue(0);
            progressBar.setString("0 / " + totalRequests);
            progressLabel.setText("Probing started (" + totalRequests + " mutations)...");
        });
    }

    @Override
    public void onProbeResult(ProbeResult_littlespidy result, int completedCount, int totalCount) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addResult(result);
            progressBar.setValue(completedCount);
            progressBar.setString(completedCount + " / " + totalCount);
            progressLabel.setText("Probed " + completedCount + " of " + totalCount);
        });
    }

    @Override
    public void onProbeFinished(boolean wasCancelled) {
        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            if (wasCancelled) {
                progressLabel.setText("Probing stopped by user.");
            } else {
                progressLabel.setText("Probing finished (" + tableModel.getRowCount() + " results).");
            }
            if (onStateChangedCallback != null) {
                onStateChangedCallback.run();
            }
        });
    }

    @Override
    public void onProbeError(String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            progressLabel.setText("Error: " + errorMessage);
        });
    }

    public HttpRequest getBaselineRequest() {
        return baselineRequest;
    }

    public HttpResponse getBaselineResponse() {
        return baselineResponse;
    }

    public VersionResultsTableModel_littlespidy getTableModel() {
        return tableModel;
    }

    public void setBaselineRequest(HttpRequest request, HttpResponse response) {
        this.baselineRequest = request;
        this.baselineResponse = response;
        updateBaselineDisplay();
        if (onStateChangedCallback != null) {
            onStateChangedCallback.run();
        }
    }

    private Runnable onStateChangedCallback;

    public void setOnStateChangedCallback(Runnable callback) {
        this.onStateChangedCallback = callback;
    }

    public boolean isUriPathSelected() {
        return uriPathCheck.isSelected();
    }

    public void setUriPathSelected(boolean sel) {
        uriPathCheck.setSelected(sel);
    }

    public boolean isHeadersSelected() {
        return headerCheck.isSelected();
    }

    public void setHeadersSelected(boolean sel) {
        headerCheck.setSelected(sel);
    }

    public boolean isQueryParamsSelected() {
        return queryParamCheck.isSelected();
    }

    public void setQueryParamsSelected(boolean sel) {
        queryParamCheck.setSelected(sel);
    }

    public boolean isContentNegotiationSelected() {
        return contentNegCheck.isSelected();
    }

    public void setContentNegotiationSelected(boolean sel) {
        contentNegCheck.setSelected(sel);
    }

    public boolean isSubdomainsSelected() {
        return subdomainCheck.isSelected();
    }

    public void setSubdomainsSelected(boolean sel) {
        subdomainCheck.setSelected(sel);
    }

    public boolean isCookiesSelected() {
        return cookieCheck.isSelected();
    }

    public void setCookiesSelected(boolean sel) {
        cookieCheck.setSelected(sel);
    }

    public String getCandidatesText() {
        return candidateInput != null ? candidateInput.getText() : "";
    }

    public void setCandidatesText(String text) {
        if (candidateInput != null && text != null) {
            candidateInput.setText(text);
            if (presetCombo != null) {
                presetCombo.setSelectedItem("Custom");
            }
            updateCandidateCountDisplay();
        }
    }

    private void updateCandidateCountDisplay() {
        if (candidateInput == null || candidateCountLabel == null) return;
        String raw = candidateInput.getText().trim();
        if (raw.isEmpty()) {
            candidateCountLabel.setText("[0 Candidates]");
            return;
        }
        int count = 0;
        for (String c : raw.split("[,\\r?\\n\\s]+")) {
            if (!c.trim().isEmpty()) count++;
        }
        candidateCountLabel.setText("[" + count + " Candidates]");
    }

    public int getThreadCount() {
        return threadSpinner != null ? (Integer) threadSpinner.getValue() : 5;
    }

    public void setThreadCount(int count) {
        if (threadSpinner != null) {
            threadSpinner.setValue(Math.max(1, Math.min(count, 20)));
        }
    }

    public int getDelayMs() {
        return delaySpinner != null ? (Integer) delaySpinner.getValue() : 0;
    }

    public void setDelayMs(int delay) {
        if (delaySpinner != null) {
            delaySpinner.setValue(Math.max(0, Math.min(delay, 5000)));
        }
    }

    public void addRestoredResult(ProbeResult_littlespidy result) {
        tableModel.addResult(result);
    }
}
