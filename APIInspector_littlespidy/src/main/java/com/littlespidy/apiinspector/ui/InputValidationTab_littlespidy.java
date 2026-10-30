// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.apiinspector.engine.InputValidationEngine_littlespidy;
import com.littlespidy.apiinspector.engine.InputValidationProgressListener_littlespidy;
import com.littlespidy.apiinspector.model.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Root Suite Tab for Input Validation Fuzzing and Testing.
 * Features:
 * Top: Runner dropdown with in-place rename, Delete Runner, Method filter,
 * dynamic Status Code multi-select dropdown, Severity filter, CSV/JSON export, and Clear.
 * Center: Sortable Results table (ID, Method, Target URL, Parameter, Payload, Status Code, Length, Indicator, Severity).
 * Bottom: 50/50 parallel side-by-side Montoya Request and Response editors.
 */
public class InputValidationTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final InputValidationEngine_littlespidy fuzzEngine;
    private InputValidationConfigPanel_littlespidy configPanel;
    private final List<Runnable> stateChangedListeners = new ArrayList<>();

    // Runner History Management
    private final List<InputValidationRun_littlespidy> savedRuns = new ArrayList<>();
    private InputValidationRun_littlespidy currentRun;
    private int runnerCounter = 1;
    private String currentRunName = "Input Validation Runner 1";
    private JComboBox<String> runnerCombo;
    private boolean updatingRunnerCombo = false;
    private JButton deleteRunnerBtn;

    // Filters UI
    private MethodFilterDropDown_littlespidy methodFilterDropDown;
    private StatusCodeFilterDropDown_littlespidy statusCodeFilterDropDown;
    private ValidationSeverityFilterDropDown_littlespidy severityFilterDropDown;

    // Results UI
    private final List<InputValidationTestResult_littlespidy> currentResults = new ArrayList<>();
    private final InputValidationResultsTableModel tableModel = new InputValidationResultsTableModel();
    private final JTable resultsTable = new JTable(tableModel);
    private TableRowSorter<InputValidationResultsTableModel> tableSorter;

    // Editors UI (50/50 Split)
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    private final JLabel statusSummaryLabel = new JLabel("Status: Ready | Total: 0");

    public InputValidationTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.fuzzEngine = new InputValidationEngine_littlespidy(api);

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();

        // Initial default runner
        currentRun = new InputValidationRun_littlespidy(currentRunName, new ArrayList<>());
        savedRuns.add(currentRun);
        updateRunnerCombo();
    }

    public InputValidationEngine_littlespidy getInputValidationEngine() {
        return fuzzEngine;
    }

    public void setConfigPanel(InputValidationConfigPanel_littlespidy configPanel) {
        this.configPanel = configPanel;
    }

    public void setOnStateChangedCallback(Runnable r) {
        if (r != null) {
            this.stateChangedListeners.add(r);
        }
    }

    private void notifyStateChanged() {
        for (Runnable r : new ArrayList<>(stateChangedListeners)) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }

    private void initComponents() {
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.50);
        mainSplit.setContinuousLayout(true);

        // Top Panel: Filters and Results Table
        JPanel resultsPanel = new JPanel(new BorderLayout(4, 4));
        resultsPanel.setBorder(new TitledBorder("Input Validation Test Results"));

        // Results Filter Bar located above results table
        JPanel resultsFilterBar = new JPanel(new BorderLayout(6, 2));
        JPanel leftFilter = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        leftFilter.add(new JLabel("Runner:"));
        runnerCombo = new JComboBox<>();
        runnerCombo.setEditable(true);
        runnerCombo.setPreferredSize(new Dimension(180, 24));
        runnerCombo.setToolTipText("Select or rename a test runner");
        runnerCombo.addActionListener(e -> onRunnerSelected());

        Component editorComp = runnerCombo.getEditor().getEditorComponent();
        if (editorComp instanceof JTextField) {
            JTextField tf = (JTextField) editorComp;
            tf.addActionListener(e -> onRenameCurrentRunner(tf.getText()));
        }
        leftFilter.add(runnerCombo);

        deleteRunnerBtn = new JButton("Delete Runner");
        deleteRunnerBtn.setToolTipText("Delete the currently selected runner from history");
        deleteRunnerBtn.addActionListener(e -> onDeleteCurrentRunner());
        leftFilter.add(deleteRunnerBtn);

        methodFilterDropDown = new MethodFilterDropDown_littlespidy();
        methodFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(methodFilterDropDown);

        statusCodeFilterDropDown = new StatusCodeFilterDropDown_littlespidy();
        statusCodeFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(statusCodeFilterDropDown);

        severityFilterDropDown = new ValidationSeverityFilterDropDown_littlespidy();
        severityFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(severityFilterDropDown);

        resultsFilterBar.add(leftFilter, BorderLayout.WEST);

        JPanel rightActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton exportCsvBtn = new JButton("Export CSV");
        exportCsvBtn.addActionListener(e -> exportToCsv());
        JButton exportJsonBtn = new JButton("Export JSON");
        exportJsonBtn.addActionListener(e -> exportToJson());
        JButton clearResultsBtn = new JButton("Clear Results");
        clearResultsBtn.addActionListener(e -> onClearResults());

        rightActions.add(exportCsvBtn);
        rightActions.add(exportJsonBtn);
        rightActions.add(clearResultsBtn);
        resultsFilterBar.add(rightActions, BorderLayout.EAST);

        resultsPanel.add(resultsFilterBar, BorderLayout.NORTH);

        // Results Table setup with TableRowSorter for sortable columns
        tableSorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(tableSorter);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setFillsViewportHeight(true);

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultsTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = resultsTable.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < currentResults.size()) {
                        displayResultDetails(currentResults.get(modelRow));
                    }
                }
            }
        });

        resultsTable.setDefaultRenderer(Object.class, new InputValidationCellRenderer());

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        resultsPanel.add(tableScrollPane, BorderLayout.CENTER);
        mainSplit.setTopComponent(resultsPanel);

        // Bottom Panel: 50/50 parallel side-by-side Montoya Request and Response editors
        if (api != null && api.userInterface() != null) {
            requestEditor = api.userInterface().createHttpRequestEditor();
            responseEditor = api.userInterface().createHttpResponseEditor();
        }

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request Viewer (Fuzzed Payload)"));
        if (requestEditor != null) {
            requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            requestPanel.add(new JScrollPane(new JTextArea("Montoya HttpRequestEditor placeholder")), BorderLayout.CENTER);
        }

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response Viewer (Server Response)"));
        if (responseEditor != null) {
            responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            responsePanel.add(new JScrollPane(new JTextArea("Montoya HttpResponseEditor placeholder")), BorderLayout.CENTER);
        }

        JSplitPane parallelViewerSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        parallelViewerSplitPane.setResizeWeight(0.5d);
        parallelViewerSplitPane.setDividerSize(6);

        mainSplit.setBottomComponent(parallelViewerSplitPane);
        add(mainSplit, BorderLayout.CENTER);
    }

    private void onRunnerSelected() {
        if (updatingRunnerCombo || runnerCombo == null) return;
        int idx = runnerCombo.getSelectedIndex();
        if (idx >= 0 && idx < savedRuns.size()) {
            loadRun(savedRuns.get(idx));
            notifyStateChanged();
        }
    }

    private void onRenameCurrentRunner(String newName) {
        if (currentRun == null || newName == null) return;
        String clean = newName.trim();
        int pIdx = clean.lastIndexOf(" (");
        if (pIdx > 0 && clean.endsWith(" results)")) {
            clean = clean.substring(0, pIdx).trim();
        }
        if (clean.isEmpty()) return;

        currentRun.setName(clean);
        currentRunName = clean;

        updatingRunnerCombo = true;
        try {
            int sel = runnerCombo.getSelectedIndex();
            runnerCombo.removeAllItems();
            for (InputValidationRun_littlespidy r : savedRuns) {
                runnerCombo.addItem(r.getName() + " (" + r.getResults().size() + " results)");
            }
            if (sel >= 0 && sel < runnerCombo.getItemCount()) {
                runnerCombo.setSelectedIndex(sel);
            }
        } finally {
            updatingRunnerCombo = false;
        }
        notifyStateChanged();
    }

    private void onDeleteCurrentRunner() {
        if (savedRuns.isEmpty() || runnerCombo == null) return;
        int idx = runnerCombo.getSelectedIndex();
        if (idx >= 0 && idx < savedRuns.size()) {
            savedRuns.remove(idx);
            if (!savedRuns.isEmpty()) {
                int nextIdx = Math.max(0, idx - 1);
                loadRun(savedRuns.get(nextIdx));
            } else {
                loadRun(null);
            }
            updateRunnerCombo();
            if (currentRun != null) {
                int newIdx = savedRuns.indexOf(currentRun);
                if (newIdx >= 0) runnerCombo.setSelectedIndex(newIdx);
            }
            clearEditors();
            notifyStateChanged();
        }
    }

    private void onClearResults() {
        currentResults.clear();
        if (currentRun != null) {
            currentRun.getResults().clear();
        }
        tableModel.fireTableDataChanged();
        updateSummary();
        clearEditors();
        updateRunnerCombo();
        notifyStateChanged();
    }

    private void loadRun(InputValidationRun_littlespidy run) {
        currentRun = run;
        currentResults.clear();
        if (run != null) {
            currentResults.addAll(run.getResults());
        }
        tableModel.fireTableDataChanged();

        for (InputValidationTestResult_littlespidy r : currentResults) {
            if (methodFilterDropDown != null && r.getMethod() != null) {
                methodFilterDropDown.registerMethod(r.getMethod());
            }
            if (statusCodeFilterDropDown != null && r.getStatusCode() > 0) {
                statusCodeFilterDropDown.registerStatusCode(r.getStatusCode());
            }
        }

        applyAllFilters();
        updateSummary();

        if (!currentResults.isEmpty()) {
            resultsTable.setRowSelectionInterval(0, 0);
        } else {
            clearEditors();
        }
    }

    private void updateRunnerCombo() {
        if (runnerCombo == null) return;
        updatingRunnerCombo = true;
        try {
            runnerCombo.removeAllItems();
            for (InputValidationRun_littlespidy r : savedRuns) {
                runnerCombo.addItem(r.getName() + " (" + r.getResults().size() + " results)");
            }
            if (currentRun != null) {
                int idx = savedRuns.indexOf(currentRun);
                if (idx >= 0) runnerCombo.setSelectedIndex(idx);
            } else if (!savedRuns.isEmpty()) {
                runnerCombo.setSelectedIndex(savedRuns.size() - 1);
            }
        } finally {
            updatingRunnerCombo = false;
        }
    }

    public void applyAllFilters() {
        if (tableSorter == null) return;

        RowFilter<InputValidationResultsTableModel, Integer> filter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends InputValidationResultsTableModel, ? extends Integer> entry) {
                int rowIdx = entry.getIdentifier();
                if (rowIdx < 0 || rowIdx >= currentResults.size()) return false;
                InputValidationTestResult_littlespidy res = currentResults.get(rowIdx);

                if (methodFilterDropDown != null && !methodFilterDropDown.isMethodSelected(res.getMethod())) {
                    return false;
                }
                if (statusCodeFilterDropDown != null && !statusCodeFilterDropDown.isStatusCodeSelected(res.getStatusCode())) {
                    return false;
                }
                if (severityFilterDropDown != null && !severityFilterDropDown.matches(res.getSeverity())) {
                    return false;
                }
                return true;
            }
        };
        tableSorter.setRowFilter(filter);
    }

    private void displayResultDetails(InputValidationTestResult_littlespidy result) {
        if (result == null) {
            clearEditors();
            return;
        }

        HttpRequest req = null;
        HttpResponse resp = null;

        if (result.getHttpRequestResponse() != null) {
            req = result.getHttpRequestResponse().request();
            if (result.getHttpRequestResponse().hasResponse()) {
                resp = result.getHttpRequestResponse().response();
            }
        } else {
            if (result.getRequestBytes() != null && result.getRequestBytes().length > 0) {
                req = HttpRequest.httpRequest(ByteArray.byteArray(result.getRequestBytes()));
            }
            if (result.getResponseBytes() != null && result.getResponseBytes().length > 0) {
                resp = HttpResponse.httpResponse(ByteArray.byteArray(result.getResponseBytes()));
            }
        }

        if (requestEditor != null) {
            requestEditor.setRequest(req);
        }
        if (responseEditor != null) {
            responseEditor.setResponse(resp);
        }
    }

    private void clearEditors() {
        if (requestEditor != null) requestEditor.setRequest(null);
        if (responseEditor != null) responseEditor.setResponse(null);
    }

    private void updateSummary() {
        int total = currentResults.size();
        int high = 0;
        int med = 0;
        int low = 0;
        int info = 0;
        for (InputValidationTestResult_littlespidy r : currentResults) {
            if (r.getSeverity() == InputValidationTestResult_littlespidy.ValidationSeverity.HIGH) high++;
            else if (r.getSeverity() == InputValidationTestResult_littlespidy.ValidationSeverity.MEDIUM) med++;
            else if (r.getSeverity() == InputValidationTestResult_littlespidy.ValidationSeverity.LOW) low++;
            else info++;
        }
        statusSummaryLabel.setText(String.format("Status: Ready | Total: %d | High: %d | Med: %d | Low: %d | Info: %d",
                total, high, med, low, info));
    }

    public void executeAttack(
            List<? extends EndpointSelectionItem_littlespidy> endpoints,
            String defaultBaseUrl,
            AuthProfile_littlespidy profile,
            String customAuthHeader,
            List<InputValidationPayloadItem_littlespidy> payloads,
            int threads,
            int delayMs,
            String runnerName) {

        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "Input Validation Runner " + (++runnerCounter);
        currentRunName = name;
        InputValidationRun_littlespidy newRun = new InputValidationRun_littlespidy(name, new ArrayList<>());
        savedRuns.add(newRun);
        loadRun(newRun);
        updateRunnerCombo();

        fuzzEngine.executeEndpointsFuzzAsync(
                endpoints,
                defaultBaseUrl,
                profile,
                customAuthHeader,
                payloads,
                threads,
                delayMs,
                new InputValidationProgressListener_littlespidy() {
                    @Override
                    public void onFuzzTestCompleted(InputValidationTestResult_littlespidy result) {
                        SwingUtilities.invokeLater(() -> {
                            currentResults.add(result);
                            newRun.addResult(result);
                            if (methodFilterDropDown != null && result.getMethod() != null) {
                                methodFilterDropDown.registerMethod(result.getMethod());
                            }
                            if (statusCodeFilterDropDown != null && result.getStatusCode() > 0) {
                                statusCodeFilterDropDown.registerStatusCode(result.getStatusCode());
                            }
                            tableModel.fireTableDataChanged();
                            applyAllFilters();
                            updateSummary();
                            updateRunnerCombo();
                            if (currentResults.size() == 1) {
                                resultsTable.setRowSelectionInterval(0, 0);
                            }
                        });
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        SwingUtilities.invokeLater(() -> {
                            if (configPanel != null) {
                                configPanel.updateProgress(current, total, statusMessage);
                            }
                        });
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        SwingUtilities.invokeLater(() -> {
                            if (configPanel != null) {
                                configPanel.onAttackFinished(fuzzEngine.isCancelled(), currentResults.size());
                            }
                            notifyStateChanged();
                        });
                    }
                }
        );
    }

    public void executeAttackForPayloads(
            HttpRequest targetRequest,
            List<InputValidationPayloadItem_littlespidy> payloads,
            int threads,
            int delayMs,
            String runnerName) {

        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "Input Validation Runner " + (++runnerCounter);
        currentRunName = name;
        InputValidationRun_littlespidy newRun = new InputValidationRun_littlespidy(name, new ArrayList<>());
        savedRuns.add(newRun);
        loadRun(newRun);
        updateRunnerCombo();

        fuzzEngine.executeIndividualPayloadsAsync(
                targetRequest,
                payloads,
                threads,
                delayMs,
                new InputValidationProgressListener_littlespidy() {
                    @Override
                    public void onFuzzTestCompleted(InputValidationTestResult_littlespidy result) {
                        SwingUtilities.invokeLater(() -> {
                            currentResults.add(result);
                            newRun.addResult(result);
                            if (methodFilterDropDown != null && result.getMethod() != null) {
                                methodFilterDropDown.registerMethod(result.getMethod());
                            }
                            if (statusCodeFilterDropDown != null && result.getStatusCode() > 0) {
                                statusCodeFilterDropDown.registerStatusCode(result.getStatusCode());
                            }
                            tableModel.fireTableDataChanged();
                            applyAllFilters();
                            updateSummary();
                            updateRunnerCombo();
                            if (currentResults.size() == 1) {
                                resultsTable.setRowSelectionInterval(0, 0);
                            }
                        });
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        SwingUtilities.invokeLater(() -> {
                            if (configPanel != null) {
                                configPanel.updateProgress(current, total, statusMessage);
                            }
                        });
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        SwingUtilities.invokeLater(() -> {
                            if (configPanel != null) {
                                configPanel.onAttackFinished(fuzzEngine.isCancelled(), currentResults.size());
                            }
                            notifyStateChanged();
                        });
                    }
                }
        );
    }

    public void executeAttack(
            HttpRequest targetRequest,
            List<InputValidationTechnique_littlespidy> techniques,
            int threads,
            int delayMs,
            String runnerName) {

        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "Input Validation Runner " + (++runnerCounter);
        currentRunName = name;
        InputValidationRun_littlespidy newRun = new InputValidationRun_littlespidy(name, new ArrayList<>());
        savedRuns.add(newRun);
        loadRun(newRun);
        updateRunnerCombo();

        fuzzEngine.executeTestsAsync(
                targetRequest,
                techniques,
                threads,
                delayMs,
                new InputValidationProgressListener_littlespidy() {
                    @Override
                    public void onFuzzTestCompleted(InputValidationTestResult_littlespidy result) {
                        SwingUtilities.invokeLater(() -> {
                            currentResults.add(result);
                            newRun.addResult(result);
                            if (methodFilterDropDown != null && result.getMethod() != null) {
                                methodFilterDropDown.registerMethod(result.getMethod());
                            }
                            if (statusCodeFilterDropDown != null && result.getStatusCode() > 0) {
                                statusCodeFilterDropDown.registerStatusCode(result.getStatusCode());
                            }
                            tableModel.fireTableDataChanged();
                            applyAllFilters();
                            updateSummary();
                            updateRunnerCombo();
                            if (currentResults.size() == 1) {
                                resultsTable.setRowSelectionInterval(0, 0);
                            }
                        });
                    }

                    @Override
                    public void onStatusUpdate(String statusMessage, int current, int total) {
                        SwingUtilities.invokeLater(() -> {
                            if (configPanel != null) {
                                configPanel.updateProgress(current, total, statusMessage);
                            }
                        });
                    }

                    @Override
                    public void onAllTestsCompleted() {
                        SwingUtilities.invokeLater(() -> {
                            if (configPanel != null) {
                                configPanel.onAttackFinished(fuzzEngine.isCancelled(), currentResults.size());
                            }
                            notifyStateChanged();
                        });
                    }
                }
        );
    }

    public void sendToInputValidation(HttpRequest request, HttpResponse response) {
        if (request == null) return;
        String path = request.path() != null ? request.path() : "/";
        String runnerName = "Fuzz - " + path;

        List<InputValidationTechnique_littlespidy> techs = InputValidationTechnique_littlespidy.getDefaultTechniques();
        executeAttack(request, techs, 4, 50, runnerName);
    }

    private void exportToCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(currentRunName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_input_validation_results.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Method,TargetURL,Parameter,Payload,StatusCode,Length,Indicator,Severity\n");
                for (InputValidationTestResult_littlespidy r : currentResults) {
                    fw.write(String.format("\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"%s\",\"%s\"\n",
                            r.getId(), r.getMethod(), r.getTargetUrl(), r.getParameterName(),
                            r.getPayload().replace("\"", "\"\""), r.getStatusCode(), r.getResponseLength(),
                            r.getDetectionIndicator().replace("\"", "\"\""), r.getSeverity().getLabel()));
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportToJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(currentRunName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_input_validation_results.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("[\n");
                for (int i = 0; i < currentResults.size(); i++) {
                    InputValidationTestResult_littlespidy r = currentResults.get(i);
                    fw.write(String.format("  {\"id\": %d, \"method\": \"%s\", \"url\": \"%s\", \"param\": \"%s\", \"payload\": \"%s\", \"status\": %d, \"length\": %d, \"indicator\": \"%s\", \"severity\": \"%s\"}%s\n",
                            r.getId(), r.getMethod(), r.getTargetUrl(), r.getParameterName(),
                            r.getPayload().replace("\"", "\\\""), r.getStatusCode(), r.getResponseLength(),
                            r.getDetectionIndicator().replace("\"", "\\\""), r.getSeverity().getLabel(),
                            (i < currentResults.size() - 1 ? "," : "")));
                }
                fw.write("]\n");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public List<InputValidationRun_littlespidy> getSavedRuns() {
        return new ArrayList<>(savedRuns);
    }

    public void setSavedRuns(List<InputValidationRun_littlespidy> runs, String selectedRunnerId, int counter) {
        savedRuns.clear();
        if (runs != null) {
            savedRuns.addAll(runs);
        }
        this.runnerCounter = Math.max(counter, savedRuns.size() + 1);

        InputValidationRun_littlespidy toSelect = null;
        if (selectedRunnerId != null) {
            for (InputValidationRun_littlespidy r : savedRuns) {
                if (selectedRunnerId.equals(r.getId())) {
                    toSelect = r;
                    break;
                }
            }
        }
        if (toSelect == null && !savedRuns.isEmpty()) {
            toSelect = savedRuns.get(savedRuns.size() - 1);
        }
        loadRun(toSelect);
        updateRunnerCombo();
    }

    public String getSelectedRunnerId() {
        return currentRun != null ? currentRun.getId() : null;
    }

    public int getRunnerCounter() {
        return runnerCounter;
    }

    public void clearAllRunners() {
        savedRuns.clear();
        currentResults.clear();
        runnerCounter = 1;
        currentRun = new InputValidationRun_littlespidy("Input Validation Runner 1", new ArrayList<>());
        savedRuns.add(currentRun);
        loadRun(currentRun);
        updateRunnerCombo();
    }

    // Results Table Model (Columns: ID, Method, Target URL, Parameter, Payload, Status Code, Length, Indicator, Severity)
    private class InputValidationResultsTableModel extends AbstractTableModel {
        private final String[] columns = {"ID", "Method", "Target URL", "Parameter", "Payload", "Status Code", "Length", "Indicator", "Severity"};

        @Override
        public int getRowCount() {
            return currentResults.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int col) {
            return columns[col];
        }

        @Override
        public Class<?> getColumnClass(int col) {
            if (col == 0 || col == 5 || col == 6) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= currentResults.size()) return "";
            InputValidationTestResult_littlespidy r = currentResults.get(rowIndex);
            switch (columnIndex) {
                case 0: return r.getId();
                case 1: return r.getMethod();
                case 2: return r.getTargetUrl();
                case 3: return r.getParameterName();
                case 4: return r.getPayload();
                case 5: return r.getStatusCode();
                case 6: return r.getResponseLength();
                case 7: return r.getDetectionIndicator();
                case 8: return r.getSeverity().getLabel();
                default: return "";
            }
        }
    }

    private static class InputValidationCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (!isSelected) {
                int modelRow = table.convertRowIndexToModel(row);
                InputValidationTab_littlespidy tab = (InputValidationTab_littlespidy) SwingUtilities.getAncestorOfClass(InputValidationTab_littlespidy.class, table);
                if (tab != null && modelRow >= 0 && modelRow < tab.currentResults.size()) {
                    InputValidationTestResult_littlespidy r = tab.currentResults.get(modelRow);
                    if (r.getSeverity() == InputValidationTestResult_littlespidy.ValidationSeverity.HIGH) {
                        c.setBackground(new Color(255, 230, 230));
                    } else if (r.getSeverity() == InputValidationTestResult_littlespidy.ValidationSeverity.MEDIUM) {
                        c.setBackground(new Color(255, 248, 220));
                    } else {
                        c.setBackground(table.getBackground());
                    }
                }
            }
            return c;
        }
    }
}
