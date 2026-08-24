package com.littlespidy.inputvalidationfuzzer.ui;

import com.littlespidy.inputvalidationfuzzer.model.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Streamlined Traffic Sweep & Discovery panel:
 * - 4 intake modes for parameter-bearing traffic
 * - Automatic deduplication
 * - Select All / Deselect All checkbox controls
 * - Comma-separated parameter name filtering
 * - Direct candidate Request & Response inspection
 * - Probe preview modal
 * - Checkbox-only 'Attack' button for launching multi-target session fuzz tabs
 *
 * @author littlespidy
 */
public class TrafficSweepPanel extends JPanel {
    private final MontoyaApi api;
    private final FuzzerConfig config;
    private final Consumer<List<TrafficCandidate>> openBatchSessionCallback;

    // ── Candidate Table & Ingestion ──
    private final TrafficCandidatesTableModel candidatesTableModel = new TrafficCandidatesTableModel();
    private final JTable candidatesTable = new JTable(candidatesTableModel);

    // ── Montoya Native Editors for Candidate Inspection ──
    private final HttpRequestEditor candidateRequestEditor;
    private final HttpResponseEditor candidateResponseEditor;

    // ── Controls & Actions ──
    private final JComboBox<String> intakeModeCombo = new JComboBox<>(new String[]{
        "All in-scope traffic with parameters",
        "All in-scope traffic with parameters - Authenticated",
        "All in-scope traffic with parameters - Unauthenticated",
        "All traffic with parameters"
    });

    private final JButton loadButton = new JButton("Load from Proxy History");
    private final JButton dedupeButton = new JButton("Deduplicate");
    private final JButton selectAllBtn = new JButton("Select All");
    private final JButton deselectAllBtn = new JButton("Deselect All");
    private final JButton exportTsvButton = new JButton("Export TSV...");
    private final JButton previewProbesBtn = new JButton("Preview Probes");
    private final JButton attackBtn = new JButton("Attack");

    private final JComboBox<String> methodFilterCombo = new JComboBox<>(new String[]{"All Methods", "GET", "POST", "PUT", "DELETE", "PATCH"});
    private final JComboBox<String> statusFilterCombo = new JComboBox<>(new String[]{"All Status", "2xx Success", "3xx Redirect", "4xx Client Error", "5xx Server Error"});
    private final JTextField paramNamesFilterField = new JTextField();
    private final JTextField searchTextField = new JTextField();

    private final JLabel statusLabel = new JLabel("Ready. Click 'Load from Proxy History' to begin.");
    private final JProgressBar progressBar = new JProgressBar();

    private final List<TrafficCandidate> rawLoadedCandidates = new ArrayList<>();

    public TrafficSweepPanel(MontoyaApi api, FuzzerConfig config, Consumer<List<TrafficCandidate>> openBatchSessionCallback) {
        this.api = api;
        this.config = config;
        this.openBatchSessionCallback = openBatchSessionCallback;

        setLayout(new BorderLayout(5, 5));

        // ── Initialize Native Editors ──
        candidateRequestEditor = api.userInterface().createHttpRequestEditor();
        candidateResponseEditor = api.userInterface().createHttpResponseEditor();

        // ── Top Action & Filter Controls ──
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel intakeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        intakeRow.add(new JLabel("Intake Mode:"));
        intakeRow.add(intakeModeCombo);
        intakeRow.add(loadButton);
        intakeRow.add(dedupeButton);
        intakeRow.add(selectAllBtn);
        intakeRow.add(deselectAllBtn);
        intakeRow.add(exportTsvButton);
        intakeRow.add(previewProbesBtn);
        intakeRow.add(attackBtn);
        topContainer.add(intakeRow);

        // ── Filter Toolbar ──
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        filterRow.setBorder(new TitledBorder("Candidate Filters"));
        filterRow.add(new JLabel("Method:"));
        filterRow.add(methodFilterCombo);
        filterRow.add(new JLabel("Status:"));
        filterRow.add(statusFilterCombo);

        filterRow.add(new JLabel("Param Names (comma-separated):"));
        paramNamesFilterField.setPreferredSize(new Dimension(180, 24));
        paramNamesFilterField.setToolTipText("e.g. id, user, token, search, action");
        filterRow.add(paramNamesFilterField);

        filterRow.add(new JLabel("Search Path/URL:"));
        searchTextField.setPreferredSize(new Dimension(140, 24));
        filterRow.add(searchTextField);

        topContainer.add(filterRow);

        JPanel statusRow = new JPanel(new BorderLayout(5, 5));
        statusRow.add(statusLabel, BorderLayout.WEST);
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(220, 16));
        statusRow.add(progressBar, BorderLayout.EAST);
        topContainer.add(statusRow);

        add(topContainer, BorderLayout.NORTH);

        // ── Main Workspace: Top Candidates Table vs Bottom Request/Response Viewers ──
        setupCandidatesTable();

        JScrollPane candidateScrollPane = new JScrollPane(candidatesTable);
        candidateScrollPane.setBorder(BorderFactory.createTitledBorder("Discovered Parameter-Bearing Endpoints"));

        JTabbedPane viewerTabs = new JTabbedPane();
        viewerTabs.addTab("Selected Request", candidateRequestEditor.uiComponent());
        viewerTabs.addTab("Selected Response", candidateResponseEditor.uiComponent());

        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, candidateScrollPane, viewerTabs);
        mainSplitPane.setResizeWeight(0.5);

        add(mainSplitPane, BorderLayout.CENTER);

        // ── Wire Listeners ──
        setupListeners();
    }

    private void setupCandidatesTable() {
        candidatesTable.setAutoCreateRowSorter(true);
        candidatesTable.getColumnModel().getColumn(0).setMaxWidth(55);
        candidatesTable.getColumnModel().getColumn(1).setMaxWidth(45);
        candidatesTable.getColumnModel().getColumn(2).setMaxWidth(75);
        candidatesTable.getColumnModel().getColumn(5).setMaxWidth(60);

        candidatesTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                int modelRow = table.convertRowIndexToModel(row);
                TrafficCandidate candidate = candidatesTableModel.getCandidateAt(modelRow);

                if (candidate != null && !isSelected) {
                    if (candidate.statusCode() >= 500) {
                        c.setBackground(new Color(255, 230, 230));
                    } else if (candidate.isAuthenticated()) {
                        c.setBackground(new Color(240, 248, 255));
                    } else {
                        c.setBackground(table.getBackground());
                    }
                }
                return c;
            }
        });

        candidatesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = candidatesTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = candidatesTable.convertRowIndexToModel(row);
                    TrafficCandidate candidate = candidatesTableModel.getCandidateAt(modelRow);
                    if (candidate != null) {
                        if (candidate.request() != null) candidateRequestEditor.setRequest(candidate.request());
                        if (candidate.response() != null) candidateResponseEditor.setResponse(candidate.response());
                    }
                }
            }
        });

        // ── Right-Click Context Menu ──
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem exportAllItem = new JMenuItem("Export All Visible Candidates to TSV...");
        JMenuItem exportSelectedItem = new JMenuItem("Export Selected Candidate(s) to TSV...");
        JMenuItem copyTsvItem = new JMenuItem("Copy Selected Candidate as TSV");

        exportAllItem.addActionListener(e -> exportCandidatesToTsv(false));
        exportSelectedItem.addActionListener(e -> exportCandidatesToTsv(true));
        copyTsvItem.addActionListener(e -> copySelectedCandidateAsTsv());

        popupMenu.add(exportAllItem);
        popupMenu.add(exportSelectedItem);
        popupMenu.addSeparator();
        popupMenu.add(copyTsvItem);

        candidatesTable.setComponentPopupMenu(popupMenu);

        // ── Keyboard Shortcut: Copy candidate as TSV ──
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        candidatesTable.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask), "copyTsv");
        candidatesTable.getActionMap().put("copyTsv", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedCandidateAsTsv();
            }
        });
    }

    private void copySelectedCandidateAsTsv() {
        int row = candidatesTable.getSelectedRow();
        if (row >= 0) {
            int modelRow = candidatesTable.convertRowIndexToModel(row);
            TrafficCandidate c = candidatesTableModel.getCandidateAt(modelRow);
            if (c != null) {
                String tsv = String.join("\t",
                    String.valueOf(c.id()),
                    sanitizeTsv(c.method()),
                    sanitizeTsv(c.host()),
                    sanitizeTsv(c.path()),
                    String.valueOf(c.parameterCount()),
                    sanitizeTsv(String.join(", ", c.parameterNames())),
                    String.valueOf(c.statusCode()),
                    String.valueOf(c.contentLength()),
                    sanitizeTsv(c.authIndicator()),
                    sanitizeTsv(c.url())
                );
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(tsv), null);
                statusLabel.setText("Copied candidate #" + c.id() + " to clipboard as TSV.");
            }
        }
    }

    private void exportCandidatesToTsv(boolean selectedOnly) {
        List<TrafficCandidate> candidatesToExport;
        if (selectedOnly) {
            candidatesToExport = candidatesTableModel.getSelectedCandidates();
            if (candidatesToExport.isEmpty()) {
                int[] selectedRows = candidatesTable.getSelectedRows();
                if (selectedRows.length > 0) {
                    candidatesToExport = new ArrayList<>();
                    for (int row : selectedRows) {
                        int modelRow = candidatesTable.convertRowIndexToModel(row);
                        TrafficCandidate c = candidatesTableModel.getCandidateAt(modelRow);
                        if (c != null) candidatesToExport.add(c);
                    }
                }
            }
            if (candidatesToExport.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No candidates selected to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
        } else {
            candidatesToExport = candidatesTableModel.getFilteredCandidates();
            if (candidatesToExport.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No candidates available to export.", "Export TSV", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Traffic Candidates to TSV");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Tab-Separated Values (*.tsv)", "tsv"));
        String defaultFileName = "InputValidationFuzzer_Candidates_" + System.currentTimeMillis() + ".tsv";
        fileChooser.setSelectedFile(new java.io.File(defaultFileName));

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().toLowerCase().endsWith(".tsv")) {
                fileToSave = new java.io.File(fileToSave.getParentFile(), fileToSave.getName() + ".tsv");
            }

            try (java.io.BufferedWriter writer = new java.io.BufferedWriter(new java.io.FileWriter(fileToSave, java.nio.charset.StandardCharsets.UTF_8))) {
                writer.write(String.join("\t",
                    "ID", "Method", "Host", "Path", "Param Count", "Param Names",
                    "Status Code", "Content Length", "Content Type", "Auth Indicator", "URL", "Timestamp"
                ));
                writer.newLine();

                for (TrafficCandidate c : candidatesToExport) {
                    String line = String.join("\t",
                        String.valueOf(c.id()),
                        sanitizeTsv(c.method()),
                        sanitizeTsv(c.host()),
                        sanitizeTsv(c.path()),
                        String.valueOf(c.parameterCount()),
                        sanitizeTsv(String.join(", ", c.parameterNames())),
                        String.valueOf(c.statusCode()),
                        String.valueOf(c.contentLength()),
                        sanitizeTsv(c.contentType()),
                        sanitizeTsv(c.authIndicator()),
                        sanitizeTsv(c.url()),
                        sanitizeTsv(c.time() != null ? c.time().toString() : "")
                    );
                    writer.write(line);
                    writer.newLine();
                }

                statusLabel.setText("Exported " + candidatesToExport.size() + " candidate(s) to " + fileToSave.getName());
                JOptionPane.showMessageDialog(
                    this,
                    "Successfully exported " + candidatesToExport.size() + " candidate(s) to:\n" + fileToSave.getAbsolutePath(),
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
        loadButton.addActionListener(e -> loadProxyHistory());
        dedupeButton.addActionListener(e -> deduplicateLoadedCandidates());
        selectAllBtn.addActionListener(e -> candidatesTableModel.selectAll(true));
        deselectAllBtn.addActionListener(e -> candidatesTableModel.selectAll(false));
        exportTsvButton.addActionListener(e -> exportCandidatesToTsv(false));
        previewProbesBtn.addActionListener(e -> showProbePreview());
        attackBtn.addActionListener(e -> launchAttackSession());

        methodFilterCombo.addActionListener(e -> applyFilters());
        statusFilterCombo.addActionListener(e -> applyFilters());
        paramNamesFilterField.addActionListener(e -> applyFilters());
        searchTextField.addActionListener(e -> applyFilters());
    }

    private void loadProxyHistory() {
        loadButton.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        statusLabel.setText("Scanning Proxy history for parameter-bearing traffic...");

        SwingWorker<List<TrafficCandidate>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<TrafficCandidate> doInBackground() {
                List<TrafficCandidate> list = new ArrayList<>();
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int idCounter = 1;
                String selectedMode = (String) intakeModeCombo.getSelectedItem();
                boolean checkScope = !"All traffic with parameters".equals(selectedMode);

                for (ProxyHttpRequestResponse item : history) {
                    HttpRequest req = item.finalRequest();
                    if (req == null) continue;

                    if (checkScope && !api.scope().isInScope(req.url())) {
                        continue;
                    }

                    List<ParsedHttpParameter> params = req.parameters();
                    List<ParsedHttpParameter> eligibleParams = params.stream()
                        .filter(p -> config.isFuzzCookieParams() || p.type() != HttpParameterType.COOKIE)
                        .collect(Collectors.toList());

                    if (eligibleParams.isEmpty()) {
                        continue;
                    }

                    HttpResponse resp = item.response();
                    int statusCode = resp != null ? resp.statusCode() : 0;
                    int contentLen = resp != null ? resp.body().length() : 0;
                    String contentType = resp != null && resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "";

                    boolean isAuth = false;
                    String authLabel = "None";
                    if (req.headerValue("Authorization") != null) {
                        isAuth = true;
                        authLabel = "Authorization Header";
                    } else if (req.headerValue("Cookie") != null && containsAuthCookie(req.headerValue("Cookie"))) {
                        isAuth = true;
                        authLabel = "Auth Cookie";
                    }

                    if ("All in-scope traffic with parameters - Authenticated".equals(selectedMode) && !isAuth) {
                        continue;
                    }
                    if ("All in-scope traffic with parameters - Unauthenticated".equals(selectedMode) && isAuth) {
                        continue;
                    }

                    List<String> paramNames = eligibleParams.stream()
                        .map(ParsedHttpParameter::name)
                        .distinct()
                        .collect(Collectors.toList());

                    String dedupeKey = TrafficDeduplicator.computeDedupeKey(req, config.isFuzzCookieParams());
                    String host = req.httpService() != null ? req.httpService().host() : "";
                    String path = req.path() != null ? req.path() : "/";

                    list.add(new TrafficCandidate(
                        idCounter++,
                        req.method(),
                        req.url(),
                        host,
                        path,
                        statusCode,
                        contentLen,
                        contentType,
                        eligibleParams.size(),
                        paramNames,
                        isAuth,
                        authLabel,
                        dedupeKey,
                        req,
                        resp,
                        ZonedDateTime.now()
                    ));
                }
                return list;
            }

            @Override
            protected void done() {
                try {
                    rawLoadedCandidates.clear();
                    rawLoadedCandidates.addAll(get());
                    deduplicateLoadedCandidates();
                    statusLabel.setText("Loaded " + rawLoadedCandidates.size() + " parameter-bearing endpoints from Proxy history.");
                } catch (Exception ex) {
                    statusLabel.setText("Error loading history: " + ex.getMessage());
                } finally {
                    loadButton.setEnabled(true);
                    progressBar.setVisible(false);
                }
            }
        };
        worker.execute();
    }

    private boolean containsAuthCookie(String cookieHeader) {
        String lower = cookieHeader.toLowerCase();
        return lower.contains("session") || lower.contains("token") || lower.contains("auth") || lower.contains("jwt") || lower.contains("phpsessid") || lower.contains("jsessionid");
    }

    private void deduplicateLoadedCandidates() {
        Map<String, TrafficCandidate> dedupedMap = new LinkedHashMap<>();
        for (TrafficCandidate c : rawLoadedCandidates) {
            dedupedMap.put(c.dedupeKey(), c);
        }
        candidatesTableModel.setCandidates(new ArrayList<>(dedupedMap.values()));
        applyFilters();
    }

    private void applyFilters() {
        String methodFilter = (String) methodFilterCombo.getSelectedItem();
        String statusFilter = (String) statusFilterCombo.getSelectedItem();
        String paramNamesQuery = paramNamesFilterField.getText().trim().toLowerCase();
        String searchQuery = searchTextField.getText().trim().toLowerCase();

        Set<String> searchParamSet = new HashSet<>();
        if (!paramNamesQuery.isEmpty()) {
            for (String p : paramNamesQuery.split("[,\\s]+")) {
                if (!p.trim().isEmpty()) {
                    searchParamSet.add(p.trim());
                }
            }
        }

        candidatesTableModel.setFilter(candidate -> {
            if (methodFilter != null && !methodFilter.equals("All Methods")) {
                if (!candidate.method().equalsIgnoreCase(methodFilter)) return false;
            }
            if (statusFilter != null && !statusFilter.equals("All Status")) {
                int sc = candidate.statusCode();
                if ("2xx Success".equals(statusFilter) && (sc < 200 || sc >= 300)) return false;
                if ("3xx Redirect".equals(statusFilter) && (sc < 300 || sc >= 400)) return false;
                if ("4xx Client Error".equals(statusFilter) && (sc < 400 || sc >= 500)) return false;
                if ("5xx Server Error".equals(statusFilter) && sc < 500) return false;
            }
            if (!searchParamSet.isEmpty()) {
                boolean matchesAnyParam = candidate.parameterNames().stream()
                    .anyMatch(pName -> searchParamSet.contains(pName.toLowerCase()));
                if (!matchesAnyParam) return false;
            }
            if (!searchQuery.isEmpty() && !candidate.url().toLowerCase().contains(searchQuery) && !candidate.path().toLowerCase().contains(searchQuery)) {
                return false;
            }
            return true;
        });

        statusLabel.setText("Showing " + candidatesTableModel.getRowCount() + " of " + candidatesTableModel.getAllCandidatesCount() + " candidates.");
    }

    private void launchAttackSession() {
        List<TrafficCandidate> selected = candidatesTableModel.getSelectedCandidates();
        if (selected.isEmpty()) {
            JOptionPane.showMessageDialog(
                this,
                "Please select at least one candidate checkbox [x] to attack.",
                "No Targets Selected",
                JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        openBatchSessionCallback.accept(selected);
    }

    private void showProbePreview() {
        int row = candidatesTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select an endpoint candidate row to preview its fuzzing probes.", "Preview", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = candidatesTable.convertRowIndexToModel(row);
        TrafficCandidate c = candidatesTableModel.getCandidateAt(modelRow);
        if (c == null || c.request() == null) return;

        List<ParsedHttpParameter> params = c.request().parameters().stream()
            .filter(p -> config.isFuzzCookieParams() || p.type() != HttpParameterType.COOKIE)
            .collect(Collectors.toList());
        List<FuzzPayload> payloads = config.getPayloads();

        StringBuilder sb = new StringBuilder();
        sb.append("=== PROBE PREVIEW FOR: ").append(c.method()).append(" ").append(c.url()).append(" ===\n\n");
        sb.append("Eligible Parameters: ").append(params.size()).append(" (").append(String.join(", ", c.parameterNames())).append(")\n");
        sb.append("Active Payloads:     ").append(payloads.size()).append("\n");
        sb.append("Total Probes Plan:   ").append(params.size() * payloads.size()).append(" requests\n\n");
        sb.append("--------------------------------------------------------------------------------\n");

        for (ParsedHttpParameter p : params) {
            sb.append("\n[PARAMETER: ").append(p.name()).append(" (").append(p.type().name()).append(")]\n");
            for (FuzzPayload pl : payloads) {
                sb.append("  -> Test: ").append(pl.name()).append(" | Injected Value: \"").append(pl.value()).append("\"\n");
            }
        }

        JTextArea textArea = new JTextArea(sb.toString());
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setEditable(false);

        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Probe Preview Plan", true);
        dialog.setSize(650, 480);
        dialog.setLocationRelativeTo(this);
        dialog.add(new JScrollPane(textArea));
        dialog.setVisible(true);
    }
}
