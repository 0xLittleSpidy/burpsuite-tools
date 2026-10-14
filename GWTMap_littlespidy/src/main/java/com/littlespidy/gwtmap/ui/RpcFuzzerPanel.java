// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.gwtmap.engine.GWTFuzzerEngine;
import com.littlespidy.gwtmap.model.GWTRpcPayload;
import com.littlespidy.gwtmap.parser.GWTRpcDeserializer;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * UI panel for automated parameter testing and GWT server exception detection.
 * Ports and enhances gwtfuzzer.
 *
 * @author littlespidy
 */
public class RpcFuzzerPanel extends JPanel {

    private final MontoyaApi api;
    private final GWTFuzzerEngine fuzzerEngine;

    // Controls
    private final JTextField urlField = new JTextField(35);
    private final JTextArea baselineBodyArea = new JTextArea(4, 40);
    private final JLabel detectionLabel = new JLabel("Parameters: Not analyzed");
    private final JTextArea stringPayloadsArea = new JTextArea(5, 30);
    private final JSpinner idRangeSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 500, 1));
    private final JCheckBox enableIdSweepsBox = new JCheckBox("Numeric ID Sweeps (+/- N)", true);

    private final JButton startBtn = new JButton("Start Testing");
    private final JButton stopBtn = new JButton("Stop");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel progressStatusLabel = new JLabel("Ready");

    // Table & Editors
    private final FuzzResultTableModel tableModel = new FuzzResultTableModel();
    private final JTable resultsTable = new JTable(tableModel);
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    private static final String DEFAULT_STRING_PAYLOADS =
            "'\n" +
            "\"\n" +
            "\\\n" +
            "' OR '1'='1\n" +
            "<script>alert(1)</script>\n" +
            "${7*7}\n" +
            "null\n" +
            "%00\n" +
            "../../../../etc/passwd\n" +
            "0\n" +
            "-1\n" +
            "9999999";

    public RpcFuzzerPanel(MontoyaApi api) {
        this.api = api;
        this.fuzzerEngine = new GWTFuzzerEngine(api);

        setLayout(new BorderLayout(6, 6));
        setBorder(new EmptyBorder(8, 8, 8, 8));

        initUI();
    }

    private void initUI() {
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        // North: Configuration
        JPanel configPanel = new JPanel(new BorderLayout(6, 6));
        configPanel.setBorder(BorderFactory.createCompoundBorder(
                new TitledBorder("GWT-RPC Parameter Fuzzer Configuration"),
                new EmptyBorder(4, 6, 6, 6)
        ));

        // Top Row: URL and Body
        JPanel reqSetupPanel = new JPanel(new BorderLayout(4, 4));
        JPanel urlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        urlRow.add(new JLabel("Target Endpoint URL:"));
        urlRow.add(urlField);
        JButton detectBtn = new JButton("Detect Parameters");
        detectBtn.addActionListener(e -> detectParameters());
        urlRow.add(detectBtn);
        urlRow.add(detectionLabel);
        reqSetupPanel.add(urlRow, BorderLayout.NORTH);

        baselineBodyArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        baselineBodyArea.setLineWrap(true);
        baselineBodyArea.setWrapStyleWord(true);
        JScrollPane bodyScroll = new JScrollPane(baselineBodyArea);
        bodyScroll.setPreferredSize(new Dimension(800, 65));
        bodyScroll.setBorder(BorderFactory.createTitledBorder("Baseline Request Body (GWT Wire Format)"));
        reqSetupPanel.add(bodyScroll, BorderLayout.CENTER);

        configPanel.add(reqSetupPanel, BorderLayout.NORTH);

        // Options Row
        JPanel optionsPanel = new JPanel(new GridLayout(1, 2, 8, 4));

        // Left Options: String Payloads
        JPanel strOptPanel = new JPanel(new BorderLayout(4, 4));
        strOptPanel.setBorder(BorderFactory.createTitledBorder("String Injection Payloads (One per line)"));
        stringPayloadsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        stringPayloadsArea.setText(DEFAULT_STRING_PAYLOADS);
        strOptPanel.add(new JScrollPane(stringPayloadsArea), BorderLayout.CENTER);
        optionsPanel.add(strOptPanel);

        // Right Options: ID Sweeps and Actions
        JPanel numOptPanel = new JPanel();
        numOptPanel.setLayout(new BoxLayout(numOptPanel, BoxLayout.Y_AXIS));
        numOptPanel.setBorder(BorderFactory.createTitledBorder("Testing Controls & Sweeps"));

        JPanel idRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        idRow.add(enableIdSweepsBox);
        idRow.add(new JLabel("Range (+/-):"));
        idRow.add(idRangeSpinner);
        numOptPanel.add(idRow);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        startBtn.addActionListener(e -> runFuzzing());
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopFuzzing());
        btnRow.add(startBtn);
        btnRow.add(stopBtn);

        JButton clearResultsBtn = new JButton("Clear Results");
        clearResultsBtn.addActionListener(e -> tableModel.clear());
        btnRow.add(clearResultsBtn);

        numOptPanel.add(btnRow);

        JPanel progressRow = new JPanel(new BorderLayout(6, 2));
        progressRow.setBorder(new EmptyBorder(4, 8, 4, 8));
        progressBar.setStringPainted(true);
        progressRow.add(progressBar, BorderLayout.CENTER);
        progressRow.add(progressStatusLabel, BorderLayout.SOUTH);
        numOptPanel.add(progressRow);

        optionsPanel.add(numOptPanel);

        configPanel.add(optionsPanel, BorderLayout.CENTER);
        add(configPanel, BorderLayout.NORTH);

        // Center: Results Table and Inspectors
        JPanel resultsPanel = new JPanel(new BorderLayout(4, 4));
        resultsPanel.setBorder(BorderFactory.createTitledBorder("Testing Results (Monitors //EX[ Serialized GWT Exceptions)"));

        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getSelectionModel().addListSelectionListener(e -> onRowSelected());

        // Custom Renderer to highlight GWT Exceptions
        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (!isSelected) {
                    GWTFuzzerEngine.FuzzResult r = tableModel.get(row);
                    if (r != null && r.isGwtException()) {
                        c.setBackground(new Color(255, 235, 235));
                        c.setForeground(new Color(180, 0, 0));
                    } else {
                        c.setBackground(Color.WHITE);
                        c.setForeground(Color.BLACK);
                    }
                }
                return c;
            }
        });

        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setPreferredSize(new Dimension(800, 160));

        // Bottom Split Pane for Request/Response inspection
        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(),
                responseEditor.uiComponent());
        editorSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorSplit);
        mainSplit.setResizeWeight(0.4);
        resultsPanel.add(mainSplit, BorderLayout.CENTER);

        add(resultsPanel, BorderLayout.CENTER);
    }

    public void setTargetUrl(String url) {
        if (url != null) {
            urlField.setText(url.trim());
        }
    }

    public void setBaselineBody(String body) {
        if (body != null) {
            baselineBodyArea.setText(body.trim());
            detectParameters();
        }
    }

    private void detectParameters() {
        String body = baselineBodyArea.getText().trim();
        if (body.isEmpty()) {
            detectionLabel.setText("Parameters: Body is empty");
            return;
        }

        GWTRpcPayload parsed = GWTRpcDeserializer.deserialize(body);
        Map<Integer, String> fuzzables = parsed.getFuzzableIndices();

        long strCount = fuzzables.values().stream().filter("%s"::equals).count();
        long numCount = fuzzables.values().stream().filter("%d"::equals).count();

        detectionLabel.setText(String.format("Found: %d String params, %d Numeric params (Total: %d)",
                strCount, numCount, fuzzables.size()));
    }

    private void runFuzzing() {
        String url = urlField.getText().trim();
        String body = baselineBodyArea.getText().trim();

        if (url.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a target endpoint URL.", "GWTMap", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (body.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a baseline GWT-RPC request body.", "GWTMap", JOptionPane.WARNING_MESSAGE);
            return;
        }

        HttpRequest baseReq;
        try {
            baseReq = HttpRequest.httpRequestFromUrl(url)
                    .withMethod("POST")
                    .withHeader("Content-Type", "text/x-gwt-rpc; charset=utf-8")
                    .withHeader("X-GWT-Permutation", "GWTMap")
                    .withHeader("X-GWT-Module-Base", url.substring(0, url.lastIndexOf('/') + 1))
                    .withBody(body);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Invalid URL: " + ex.getMessage(), "GWTMap", JOptionPane.ERROR_MESSAGE);
            return;
        }

        List<String> payloads = Arrays.stream(stringPayloadsArea.getText().split("\n"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();

        int idRange = enableIdSweepsBox.isSelected() ? (Integer) idRangeSpinner.getValue() : 0;

        tableModel.clear();
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        progressBar.setValue(0);
        progressStatusLabel.setText("Fuzzing in progress...");

        fuzzerEngine.startFuzzing(
                baseReq,
                payloads,
                idRange,
                result -> SwingUtilities.invokeLater(() -> tableModel.addResult(result)),
                currentProgress -> SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(currentProgress);
                    progressStatusLabel.setText("Completed probes: " + currentProgress);
                }),
                () -> SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                    progressStatusLabel.setText("Testing completed. Total probes: " + tableModel.getRowCount());
                })
        );
    }

    private void stopFuzzing() {
        fuzzerEngine.cancel();
        stopBtn.setEnabled(false);
        startBtn.setEnabled(true);
        progressStatusLabel.setText("Cancelled by user.");
    }

    private void onRowSelected() {
        int row = resultsTable.getSelectedRow();
        if (row >= 0 && row < tableModel.getRowCount()) {
            GWTFuzzerEngine.FuzzResult r = tableModel.get(row);
            if (r != null) {
                if (r.getRequest() != null) requestEditor.setRequest(r.getRequest());
                if (r.getResponse() != null) responseEditor.setResponse(r.getResponse());
            }
        }
    }

    // ── Table Model ──────────────────────────────────────────────────────────

    private static class FuzzResultTableModel extends AbstractTableModel {
        private final String[] columns = {"ID", "Type", "Payload", "Status", "Length", "Time (ms)", "GWT Exception", "Error Details"};
        private final List<GWTFuzzerEngine.FuzzResult> results = new ArrayList<>();

        public void addResult(GWTFuzzerEngine.FuzzResult r) {
            results.add(r);
            fireTableRowsInserted(results.size() - 1, results.size() - 1);
        }

        public void clear() {
            results.clear();
            fireTableDataChanged();
        }

        public GWTFuzzerEngine.FuzzResult get(int row) {
            if (row >= 0 && row < results.size()) return results.get(row);
            return null;
        }

        @Override
        public int getRowCount() { return results.size(); }

        @Override
        public int getColumnCount() { return columns.length; }

        @Override
        public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            GWTFuzzerEngine.FuzzResult r = results.get(row);
            return switch (col) {
                case 0 -> r.getId();
                case 1 -> r.getAttackType();
                case 2 -> r.getPayload();
                case 3 -> r.getStatusCode();
                case 4 -> r.getResponseLength();
                case 5 -> r.getResponseTimeMs();
                case 6 -> r.isGwtException() ? "YES" : "NO";
                case 7 -> r.getErrorNotes();
                default -> "";
            };
        }
    }
}
