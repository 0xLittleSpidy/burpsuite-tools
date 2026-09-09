// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;
import com.littlespidy.convertposttoget.model.PostCandidate;
import com.littlespidy.convertposttoget.model.PostDeduplicator;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
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
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Dedicated POST Traffic Discovery panel adhering strictly to extension_architecture.md:
 * - 4 intake modes for POST traffic with background ingestion
 * - Core Four Triage Filters: Multi-select Status, Domain with URL sanitization, Non-destructive In-Scope, Method/Content-Type
 * - MultiSelectFilterButtons for Status, Content-Type, and Parameter-Types
 * - Row Pinning (Pin Selected / Clear Pins)
 * - 300ms Debounced search with Regex, Case-sensitivity, and Inversion options
 * - Full Burp Suite interoperability: Send to Repeater, Intruder, and Organizer
 * - Live Metrics: "Total: X | Displayed: Y (Z% filtered)"
 * - Direct candidate Request & Response inspection with Montoya editors
 * - Batch-aware checkbox target selection for launching conversion sessions
 *
 * @author littlespidy
 */
public class PostTrafficSweepPanel extends JPanel {
    private final MontoyaApi api;
    private final ConvertPostToGetConfig config;
    private final Consumer<List<PostCandidate>> openBatchSessionCallback;

    private final PostCandidatesTableModel candidatesTableModel = new PostCandidatesTableModel();
    private final JTable candidatesTable = new JTable(candidatesTableModel);

    private final HttpRequestEditor candidateRequestEditor;
    private final HttpResponseEditor candidateResponseEditor;

    // ── Intake Controls ──
    private final JComboBox<String> intakeModeCombo = new JComboBox<>(new String[]{
        "All in-scope POST traffic with parameters",
        "All in-scope POST traffic with parameters - Authenticated",
        "All in-scope POST traffic with parameters - Unauthenticated",
        "All POST traffic with parameters"
    });

    private final JButton loadButton = new JButton("Load from Proxy History");
    private final JButton dedupeButton = new JButton("Deduplicate");
    private final JButton selectAllBtn = new JButton("Select All");
    private final JButton deselectAllBtn = new JButton("Deselect All");
    private final JButton pinSelectedBtn = new JButton("Pin Selected");
    private final JButton clearPinsBtn = new JButton("Clear Pins");
    private final JButton exportTsvButton = new JButton("Export TSV...");
    private final JButton attackBtn = new JButton("\u26A1 Attack");

    // ── Core Four & Triage Filter Components ──
    private final JTextField domainFilterField = new JTextField(12);

    private final MultiSelectFilterButton statusFilterBtn = new MultiSelectFilterButton(
        "Status",
        List.of(
            "All Status Codes",
            "2xx Success",
            "200 OK",
            "201 Created",
            "204 No Content",
            "3xx Redirect",
            "301 / 302 Redirect",
            "304 Not Modified",
            "4xx Client Error",
            "400 Bad Request",
            "401 Unauthorized",
            "403 Forbidden",
            "404 Not Found",
            "5xx Server Error",
            "500 Internal Error"
        ),
        sel -> triggerDebouncedFilter()
    );

    private final MultiSelectFilterButton contentTypeFilterBtn = new MultiSelectFilterButton(
        "Content-Type",
        List.of(
            "All Content-Types",
            "Form URL-Encoded",
            "JSON",
            "Multipart Form-Data",
            "XML",
            "Plain Text",
            "Other"
        ),
        sel -> triggerDebouncedFilter()
    );

    private final MultiSelectFilterButton paramTypeFilterBtn = new MultiSelectFilterButton(
        "Param Type",
        List.of(
            "All Parameter Types",
            "Body Parameters",
            "JSON Top-Level Keys",
            "Multipart Parameters",
            "URL Query Parameters",
            "XML Elements"
        ),
        sel -> triggerDebouncedFilter()
    );

    private final JTextField paramNamesFilterField = new JTextField(12);
    private final JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-Scope Only", false);
    private final JTextField searchTextField = new JTextField(12);
    private final JCheckBox regexSearchCheckBox = new JCheckBox("Regex", false);
    private final JCheckBox matchCaseCheckBox = new JCheckBox("Match Case", false);
    private final JCheckBox invertSearchCheckBox = new JCheckBox("Invert", false);

    private final JButton resetFiltersBtn = new JButton("Reset Filters");

    // ── Metric Labels & Progress ──
    private final JLabel statusLabel = new JLabel("Ready. Click 'Load from Proxy History' to begin.");
    private final JLabel statsLabel = new JLabel("Total: 0 | Displayed: 0");
    private final JProgressBar progressBar = new JProgressBar();

    // ── Debounce Timer (300ms) ──
    private final javax.swing.Timer filterDebounceTimer = new javax.swing.Timer(300, e -> applyFilters());
    {
        filterDebounceTimer.setRepeats(false);
    }

    private final List<PostCandidate> rawLoadedCandidates = new ArrayList<>();

    public PostTrafficSweepPanel(MontoyaApi api, ConvertPostToGetConfig config, Consumer<List<PostCandidate>> openBatchSessionCallback) {
        this.api = api;
        this.config = config;
        this.openBatchSessionCallback = openBatchSessionCallback;

        setLayout(new BorderLayout(5, 5));

        candidateRequestEditor = api.userInterface().createHttpRequestEditor();
        candidateResponseEditor = api.userInterface().createHttpResponseEditor();

        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // ── Row 1: Intake & Action Controls ──
        JPanel intakeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        intakeRow.add(new JLabel("Intake Mode:"));
        intakeRow.add(intakeModeCombo);
        intakeRow.add(loadButton);
        intakeRow.add(dedupeButton);
        intakeRow.add(new JSeparator(SwingConstants.VERTICAL));
        intakeRow.add(selectAllBtn);
        intakeRow.add(deselectAllBtn);
        intakeRow.add(pinSelectedBtn);
        intakeRow.add(clearPinsBtn);
        intakeRow.add(new JSeparator(SwingConstants.VERTICAL));
        intakeRow.add(exportTsvButton);
        attackBtn.setFont(attackBtn.getFont().deriveFont(Font.BOLD));
        intakeRow.add(attackBtn);
        topContainer.add(intakeRow);

        // ── Row 2: Core Triage Filter Bar ──
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        filterRow.setBorder(new TitledBorder("Core Triage & Parameter Filters"));

        filterRow.add(new JLabel("Domain:"));
        domainFilterField.setToolTipText("Filter by domain or host (e.g. api.target.com, *.target.com)");
        domainFilterField.getDocument().addDocumentListener((FilterUtils.SimpleDocumentListener) this::triggerDebouncedFilter);
        filterRow.add(domainFilterField);

        filterRow.add(statusFilterBtn);
        filterRow.add(contentTypeFilterBtn);
        filterRow.add(paramTypeFilterBtn);

        filterRow.add(new JLabel("Param Names:"));
        paramNamesFilterField.setToolTipText("Search parameter names (e.g. id, token, csrf, action)");
        paramNamesFilterField.getDocument().addDocumentListener((FilterUtils.SimpleDocumentListener) this::triggerDebouncedFilter);
        filterRow.add(paramNamesFilterField);

        inScopeOnlyCheckBox.setToolTipText("Show only items within Burp Target Scope");
        inScopeOnlyCheckBox.addActionListener(e -> applyFilters());
        filterRow.add(inScopeOnlyCheckBox);

        filterRow.add(resetFiltersBtn);
        topContainer.add(filterRow);

        // ── Row 3: Search Bar & Preset Chips ──
        JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        searchRow.add(new JLabel("Search Path/URL:"));
        searchTextField.setToolTipText("Search URL or path");
        searchTextField.getDocument().addDocumentListener((FilterUtils.SimpleDocumentListener) this::triggerDebouncedFilter);
        searchRow.add(searchTextField);
        searchRow.add(regexSearchCheckBox);
        searchRow.add(matchCaseCheckBox);
        searchRow.add(invertSearchCheckBox);

        regexSearchCheckBox.addActionListener(e -> triggerDebouncedFilter());
        matchCaseCheckBox.addActionListener(e -> triggerDebouncedFilter());
        invertSearchCheckBox.addActionListener(e -> triggerDebouncedFilter());

        searchRow.add(new JSeparator(SwingConstants.VERTICAL));
        searchRow.add(new JLabel("Presets:"));

        JButton chipAll = createPresetChip("All Candidates", () -> resetAllFilters());
        JButton chipJson = createPresetChip("JSON Payloads", () -> {
            resetAllFilters();
            contentTypeFilterBtn.setSelected(Set.of("JSON"));
            paramTypeFilterBtn.setSelected(Set.of("JSON Top-Level Keys"));
            applyFilters();
        });
        JButton chipForm = createPresetChip("Form Encoded", () -> {
            resetAllFilters();
            contentTypeFilterBtn.setSelected(Set.of("Form URL-Encoded"));
            applyFilters();
        });
        JButton chipAuth = createPresetChip("Has Auth / Token", () -> {
            resetAllFilters();
            paramNamesFilterField.setText("csrf, token, auth, session, api_key");
            applyFilters();
        });

        searchRow.add(chipAll);
        searchRow.add(chipJson);
        searchRow.add(chipForm);
        searchRow.add(chipAuth);

        topContainer.add(searchRow);

        // ── Row 4: Status & Progress Row ──
        JPanel statusRow = new JPanel(new BorderLayout(5, 5));
        statusRow.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        statusRow.add(statusLabel, BorderLayout.WEST);

        JPanel statusRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        statusRight.add(statsLabel);
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(180, 14));
        statusRight.add(progressBar);
        statusRow.add(statusRight, BorderLayout.EAST);
        topContainer.add(statusRow);

        add(topContainer, BorderLayout.NORTH);

        // ── Candidates Table & Detail Editors ──
        setupCandidatesTable();

        JScrollPane candidateScrollPane = new JScrollPane(candidatesTable);
        candidateScrollPane.setBorder(BorderFactory.createTitledBorder("Discovered POST Endpoints"));

        JTabbedPane viewerTabs = new JTabbedPane();
        viewerTabs.addTab("Selected POST Request", candidateRequestEditor.uiComponent());
        viewerTabs.addTab("Selected POST Response", candidateResponseEditor.uiComponent());

        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, candidateScrollPane, viewerTabs);
        mainSplitPane.setResizeWeight(0.52);

        add(mainSplitPane, BorderLayout.CENTER);

        setupListeners();
    }

    private JButton createPresetChip(String label, Runnable action) {
        JButton btn = new JButton(label);
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        btn.setMargin(new Insets(1, 6, 1, 6));
        btn.addActionListener(e -> action.run());
        return btn;
    }

    private void triggerDebouncedFilter() {
        filterDebounceTimer.restart();
    }

    private void resetAllFilters() {
        domainFilterField.setText("");
        paramNamesFilterField.setText("");
        searchTextField.setText("");
        statusFilterBtn.clearSelection();
        contentTypeFilterBtn.clearSelection();
        paramTypeFilterBtn.clearSelection();
        inScopeOnlyCheckBox.setSelected(false);
        regexSearchCheckBox.setSelected(false);
        matchCaseCheckBox.setSelected(false);
        invertSearchCheckBox.setSelected(false);
        candidatesTableModel.clearPins();
        applyFilters();
    }

    private void setupCandidatesTable() {
        candidatesTable.setAutoCreateRowSorter(true);
        candidatesTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        candidatesTable.getColumnModel().getColumn(0).setMaxWidth(50); // Select
        candidatesTable.getColumnModel().getColumn(1).setMaxWidth(45); // #
        candidatesTable.getColumnModel().getColumn(2).setMaxWidth(65); // Method
        candidatesTable.getColumnModel().getColumn(6).setMaxWidth(60); // Params
        candidatesTable.getColumnModel().getColumn(8).setMaxWidth(75); // POST Status
        candidatesTable.getColumnModel().getColumn(9).setMaxWidth(80); // Length

        candidatesTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                int modelRow = table.convertRowIndexToModel(row);
                PostCandidate candidate = candidatesTableModel.getCandidateAt(modelRow);

                if (candidate != null && !isSelected) {
                    if (candidatesTableModel.isPinned(candidate.id())) {
                        c.setBackground(new Color(255, 250, 205)); // Pinned highlight
                    } else if (candidate.statusCode() >= 500) {
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
                    PostCandidate candidate = candidatesTableModel.getCandidateAt(modelRow);
                    if (candidate != null) {
                        if (candidate.request() != null) candidateRequestEditor.setRequest(candidate.request());
                        if (candidate.response() != null) candidateResponseEditor.setResponse(candidate.response());
                    }
                }
            }
        });

        // ── Right-Click Context Menu (Burp Interoperability) ──
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem sendRepeaterItem = new JMenuItem("Send to Repeater");
        sendRepeaterItem.addActionListener(e -> sendSelectedToRepeater());

        JMenuItem sendIntruderItem = new JMenuItem("Send to Intruder");
        sendIntruderItem.addActionListener(e -> sendSelectedToIntruder());

        JMenuItem sendOrganizerItem = new JMenuItem("Send to Organizer");
        sendOrganizerItem.addActionListener(e -> sendSelectedToOrganizer());

        JMenuItem pinItem = new JMenuItem("Pin Selected");
        pinItem.addActionListener(e -> pinSelectedRows());

        JMenuItem clearPinsItem = new JMenuItem("Clear Pins");
        clearPinsItem.addActionListener(e -> {
            candidatesTableModel.clearPins();
            applyFilters();
        });

        JMenuItem exportAllItem = new JMenuItem("Export All Visible Candidates to TSV...");
        JMenuItem exportSelectedItem = new JMenuItem("Export Selected Candidate(s) to TSV...");
        JMenuItem copyTsvItem = new JMenuItem("Copy Selected Candidate as TSV");

        exportAllItem.addActionListener(e -> exportCandidatesToTsv(false));
        exportSelectedItem.addActionListener(e -> exportCandidatesToTsv(true));
        copyTsvItem.addActionListener(e -> copySelectedCandidateAsTsv());

        popupMenu.add(sendRepeaterItem);
        popupMenu.add(sendIntruderItem);
        popupMenu.add(sendOrganizerItem);
        popupMenu.addSeparator();
        popupMenu.add(pinItem);
        popupMenu.add(clearPinsItem);
        popupMenu.addSeparator();
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

    private void pinSelectedRows() {
        int[] rows = candidatesTable.getSelectedRows();
        for (int r : rows) {
            int modelRow = candidatesTable.convertRowIndexToModel(r);
            PostCandidate c = candidatesTableModel.getCandidateAt(modelRow);
            if (c != null) {
                candidatesTableModel.pin(c.id());
            }
        }
        applyFilters();
    }

    private void sendSelectedToRepeater() {
        int[] rows = candidatesTable.getSelectedRows();
        if (rows.length == 0) return;
        for (int r : rows) {
            int modelRow = candidatesTable.convertRowIndexToModel(r);
            PostCandidate c = candidatesTableModel.getCandidateAt(modelRow);
            if (c != null && c.request() != null) {
                String tabName = c.method() + " " + c.host() + c.path();
                api.repeater().sendToRepeater(c.request(), tabName);
            }
        }
        statusLabel.setText("Sent " + rows.length + " request(s) to Repeater.");
    }

    private void sendSelectedToIntruder() {
        int[] rows = candidatesTable.getSelectedRows();
        if (rows.length == 0) return;
        for (int r : rows) {
            int modelRow = candidatesTable.convertRowIndexToModel(r);
            PostCandidate c = candidatesTableModel.getCandidateAt(modelRow);
            if (c != null && c.request() != null) {
                api.intruder().sendToIntruder(c.request());
            }
        }
        statusLabel.setText("Sent " + rows.length + " request(s) to Intruder.");
    }

    private void sendSelectedToOrganizer() {
        int[] rows = candidatesTable.getSelectedRows();
        if (rows.length == 0) return;
        int count = 0;
        for (int r : rows) {
            int modelRow = candidatesTable.convertRowIndexToModel(r);
            PostCandidate c = candidatesTableModel.getCandidateAt(modelRow);
            if (c != null && c.request() != null) {
                HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(c.request(), c.response());
                api.organizer().sendToOrganizer(rr);
                count++;
            }
        }
        statusLabel.setText("Sent " + count + " request(s) to Organizer.");
    }

    private void copySelectedCandidateAsTsv() {
        int[] rows = candidatesTable.getSelectedRows();
        if (rows.length == 0) return;
        StringBuilder sb = new StringBuilder();
        for (int r : rows) {
            int modelRow = candidatesTable.convertRowIndexToModel(r);
            PostCandidate c = candidatesTableModel.getCandidateAt(modelRow);
            if (c != null) {
                sb.append(String.join("\t",
                    String.valueOf(c.id()),
                    sanitizeTsv(c.method()),
                    sanitizeTsv(c.host()),
                    sanitizeTsv(c.path()),
                    sanitizeTsv(c.contentType()),
                    String.valueOf(c.parameterCount()),
                    sanitizeTsv(String.join(", ", c.parameterNames())),
                    String.valueOf(c.statusCode()),
                    String.valueOf(c.contentLength()),
                    sanitizeTsv(c.authIndicator()),
                    sanitizeTsv(c.url())
                )).append("\n");
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString().trim()), null);
        statusLabel.setText("Copied " + rows.length + " candidate(s) to clipboard as TSV.");
    }

    private void exportCandidatesToTsv(boolean selectedOnly) {
        List<PostCandidate> candidatesToExport;
        if (selectedOnly) {
            candidatesToExport = candidatesTableModel.getSelectedCandidates();
            if (candidatesToExport.isEmpty()) {
                int[] selectedRows = candidatesTable.getSelectedRows();
                if (selectedRows.length > 0) {
                    candidatesToExport = new ArrayList<>();
                    for (int row : selectedRows) {
                        int modelRow = candidatesTable.convertRowIndexToModel(row);
                        PostCandidate c = candidatesTableModel.getCandidateAt(modelRow);
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
        fileChooser.setDialogTitle("Export POST Candidates to TSV");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Tab-Separated Values (*.tsv)", "tsv"));
        String defaultFileName = "ConvertPostToGet_Candidates_" + System.currentTimeMillis() + ".tsv";
        fileChooser.setSelectedFile(new java.io.File(defaultFileName));

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().toLowerCase().endsWith(".tsv")) {
                fileToSave = new java.io.File(fileToSave.getParentFile(), fileToSave.getName() + ".tsv");
            }

            try (java.io.BufferedWriter writer = new java.io.BufferedWriter(new java.io.FileWriter(fileToSave, java.nio.charset.StandardCharsets.UTF_8))) {
                writer.write(String.join("\t",
                    "ID", "Method", "Host", "Path", "Content-Type", "Param Count", "Param Names",
                    "POST Status", "Content Length", "Auth Indicator", "URL", "Timestamp"
                ));
                writer.newLine();

                for (PostCandidate c : candidatesToExport) {
                    String line = String.join("\t",
                        String.valueOf(c.id()),
                        sanitizeTsv(c.method()),
                        sanitizeTsv(c.host()),
                        sanitizeTsv(c.path()),
                        sanitizeTsv(c.contentType()),
                        String.valueOf(c.parameterCount()),
                        sanitizeTsv(String.join(", ", c.parameterNames())),
                        String.valueOf(c.statusCode()),
                        String.valueOf(c.contentLength()),
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
        pinSelectedBtn.addActionListener(e -> pinSelectedRows());
        clearPinsBtn.addActionListener(e -> {
            candidatesTableModel.clearPins();
            applyFilters();
        });
        exportTsvButton.addActionListener(e -> exportCandidatesToTsv(false));
        attackBtn.addActionListener(e -> launchAttackSession());
        resetFiltersBtn.addActionListener(e -> resetAllFilters());
    }

    private void loadProxyHistory() {
        loadButton.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        statusLabel.setText("Scanning Proxy history for POST traffic...");

        SwingWorker<List<PostCandidate>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<PostCandidate> doInBackground() {
                List<PostCandidate> list = new ArrayList<>();
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int idCounter = 1;
                String selectedMode = (String) intakeModeCombo.getSelectedItem();
                boolean checkScope = !"All POST traffic with parameters".equals(selectedMode);

                for (ProxyHttpRequestResponse item : history) {
                    HttpRequest req = item.finalRequest();
                    if (req == null || !req.method().equalsIgnoreCase("POST")) continue;

                    if (checkScope && !api.scope().isInScope(req.url())) {
                        continue;
                    }

                    List<ParsedHttpParameter> params = req.parameters();
                    List<ParsedHttpParameter> eligibleParams = params.stream()
                        .filter(p -> p.type() != HttpParameterType.COOKIE)
                        .collect(Collectors.toList());

                    // Require at least 1 parameter or a non-empty body
                    if (eligibleParams.isEmpty() && req.bodyToString().trim().isEmpty()) {
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

                    if ("All in-scope POST traffic with parameters - Authenticated".equals(selectedMode) && !isAuth) {
                        continue;
                    }
                    if ("All in-scope POST traffic with parameters - Unauthenticated".equals(selectedMode) && isAuth) {
                        continue;
                    }

                    List<String> paramNames = eligibleParams.stream()
                        .map(ParsedHttpParameter::name)
                        .distinct()
                        .collect(Collectors.toList());

                    Set<String> paramTypes = new HashSet<>();
                    for (ParsedHttpParameter p : eligibleParams) {
                        if (p.type() == HttpParameterType.BODY) paramTypes.add("BODY");
                        else if (p.type() == HttpParameterType.URL) paramTypes.add("URL");
                        else if (p.type() == HttpParameterType.JSON) paramTypes.add("JSON");
                        else if (p.type() == HttpParameterType.MULTIPART_ATTRIBUTE) paramTypes.add("MULTIPART");
                        else if (p.type() == HttpParameterType.XML || p.type() == HttpParameterType.XML_ATTRIBUTE) paramTypes.add("XML");
                    }
                    String reqContentType = req.headerValue("Content-Type");
                    if (reqContentType != null) {
                        String lower = reqContentType.toLowerCase();
                        if (lower.contains("json")) paramTypes.add("JSON");
                        if (lower.contains("form-urlencoded")) paramTypes.add("BODY");
                        if (lower.contains("multipart")) paramTypes.add("MULTIPART");
                        if (lower.contains("xml")) paramTypes.add("XML");
                    }

                    String dedupeKey = PostDeduplicator.computeDedupeKey(req);
                    String host = req.httpService() != null ? req.httpService().host() : "";
                    String path = req.path() != null ? req.path() : "/";

                    list.add(new PostCandidate(
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
                        paramTypes,
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
                    statusLabel.setText("Loaded " + rawLoadedCandidates.size() + " POST endpoints from Proxy history.");
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
        Map<String, PostCandidate> dedupedMap = new LinkedHashMap<>();
        for (PostCandidate c : rawLoadedCandidates) {
            dedupedMap.put(c.dedupeKey(), c);
        }
        candidatesTableModel.setCandidates(new ArrayList<>(dedupedMap.values()));
        applyFilters();
    }

    private void applyFilters() {
        String domainFilter = domainFilterField.getText().trim();
        Set<String> selectedStatusCodes = statusFilterBtn.getSelected();
        Set<String> selectedContentTypes = contentTypeFilterBtn.getSelected();
        Set<String> selectedParamTypes = paramTypeFilterBtn.getSelected();
        String paramNamesQuery = paramNamesFilterField.getText().trim().toLowerCase();
        boolean inScopeOnly = inScopeOnlyCheckBox.isSelected();

        String rawSearch = searchTextField.getText();
        boolean isRegex = regexSearchCheckBox.isSelected();
        boolean matchCase = matchCaseCheckBox.isSelected();
        boolean invertSearch = invertSearchCheckBox.isSelected();

        Pattern searchPattern = null;
        if (isRegex && !rawSearch.trim().isEmpty()) {
            try {
                int flags = matchCase ? 0 : Pattern.CASE_INSENSITIVE;
                searchPattern = Pattern.compile(rawSearch, flags);
            } catch (Exception ignored) {}
        }
        final Pattern finalSearchPattern = searchPattern;

        Set<String> searchParamSet = new HashSet<>();
        if (!paramNamesQuery.isEmpty()) {
            for (String p : paramNamesQuery.split("[,\\s]+")) {
                if (!p.trim().isEmpty()) {
                    searchParamSet.add(p.trim());
                }
            }
        }

        candidatesTableModel.setFilter(candidate -> {
            // 1. Domain filter (with sanitization)
            if (!FilterUtils.matchesDomain(candidate.host(), domainFilter)) {
                return false;
            }

            // 2. Status code multi-select filter
            if (!FilterUtils.matchesStatusCode(candidate.statusCode(), selectedStatusCodes)) {
                return false;
            }

            // 3. Content-Type multi-select filter
            if (!FilterUtils.matchesContentType(candidate.contentType(), selectedContentTypes)) {
                return false;
            }

            // 4. Parameter Type filter
            if (!FilterUtils.matchesParamTypes(candidate.parameterTypes(), selectedParamTypes)) {
                return false;
            }

            // 5. In-Scope non-destructive view filter
            if (!FilterUtils.matchesScope(api, candidate.url(), inScopeOnly)) {
                return false;
            }

            // 6. Parameter name contains
            if (!searchParamSet.isEmpty()) {
                boolean matchesAnyParam = candidate.parameterNames().stream()
                    .anyMatch(pName -> searchParamSet.contains(pName.toLowerCase()) || searchParamSet.stream().anyMatch(sp -> pName.toLowerCase().contains(sp)));
                if (!matchesAnyParam) return false;
            }

            // 7. Search text (URL / Path) with Regex, Match Case, Invert
            if (!rawSearch.trim().isEmpty()) {
                boolean matchesSearch;
                String targetUrl = candidate.url();
                String targetPath = candidate.path();

                if (finalSearchPattern != null) {
                    matchesSearch = finalSearchPattern.matcher(targetUrl).find() || finalSearchPattern.matcher(targetPath).find();
                } else {
                    String query = matchCase ? rawSearch : rawSearch.toLowerCase();
                    String u = matchCase ? targetUrl : targetUrl.toLowerCase();
                    String p = matchCase ? targetPath : targetPath.toLowerCase();
                    matchesSearch = u.contains(query) || p.contains(query);
                }

                if (invertSearch) {
                    matchesSearch = !matchesSearch;
                }
                if (!matchesSearch) return false;
            }

            return true;
        });

        int total = candidatesTableModel.getAllCandidatesCount();
        int displayed = candidatesTableModel.getRowCount();
        int pinned = candidatesTableModel.getPinnedCount();
        int pct = total > 0 ? (int) Math.round((1.0 - ((double) displayed / total)) * 100) : 0;

        statsLabel.setText(String.format("Total: %d | Displayed: %d (%d%% filtered)%s",
            total, displayed, pct, pinned > 0 ? " | Pinned: " + pinned : ""));
        statusLabel.setText("Displaying " + displayed + " of " + total + " candidates.");
    }

    private void launchAttackSession() {
        List<PostCandidate> selected = candidatesTableModel.getSelectedCandidates();
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
}
