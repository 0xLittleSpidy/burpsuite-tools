// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.apiinspector.engine.PostToGetEngine_littlespidy;
import com.littlespidy.apiinspector.engine.PostToGetProgressListener_littlespidy;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.PostToGetRun_littlespidy;
import com.littlespidy.apiinspector.model.PostToGetTestResult_littlespidy;

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
 * Root Suite Tab for automated POST-to-GET method tampering testing.
 * Features:
 * Top: Runner dropdown with in-place rename, Delete Runner, Method filter,
 * dynamic Status Code multi-select dropdown, CSV/JSON export, and Clear.
 * Center: Sortable Results table (ID, Endpoint Path, Original Method, Mutated Method,
 * Query Parameters, Original Status, Mutated Status, Length Diff, Verdict).
 * Bottom: 50/50 side-by-side comparison of Baseline POST vs Mutated GET messages.
 */
public class PostToGetTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final PostToGetEngine_littlespidy engine;
    private PostToGetConfigPanel_littlespidy configPanel;
    private final List<Runnable> stateChangedListeners = new ArrayList<>();

    // Runner History Management
    private final List<PostToGetRun_littlespidy> savedRuns = new ArrayList<>();
    private PostToGetRun_littlespidy currentRun;
    private int runnerCounter = 1;
    private String currentRunName = "POST to GET Runner 1";
    private JComboBox<String> runnerCombo;
    private boolean updatingRunnerCombo = false;
    private JButton deleteRunnerBtn;

    // Filters UI
    private MethodFilterDropDown_littlespidy methodFilterDropDown;
    private StatusCodeFilterDropDown_littlespidy statusCodeFilterDropDown;

    // Results UI
    private final List<PostToGetTestResult_littlespidy> currentResults = new ArrayList<>();
    private final PostToGetResultsTableModel tableModel = new PostToGetResultsTableModel();
    private final JTable resultsTable = new JTable(tableModel);
    private TableRowSorter<PostToGetResultsTableModel> tableSorter;

    // Editors UI (Comparison View: Left = Baseline POST, Right = Mutated GET)
    private HttpRequestEditor baselineReqEditor;
    private HttpResponseEditor baselineRespEditor;
    private HttpRequestEditor mutatedReqEditor;
    private HttpResponseEditor mutatedRespEditor;

    private JTabbedPane baselineTabbedPane;
    private JTabbedPane mutatedTabbedPane;

    private final JLabel statusSummaryLabel = new JLabel("Status: Ready | Total: 0");

    public PostToGetTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.engine = new PostToGetEngine_littlespidy(api);

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();

        // Initial default runner
        currentRun = new PostToGetRun_littlespidy(currentRunName, new ArrayList<>());
        savedRuns.add(currentRun);
        updateRunnerCombo();
    }

    public PostToGetEngine_littlespidy getEngine() {
        return engine;
    }

    public void setConfigPanel(PostToGetConfigPanel_littlespidy configPanel) {
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
        resultsPanel.setBorder(new TitledBorder("POST to GET Method Tampering Results"));

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

        resultsTable.setDefaultRenderer(Object.class, new PostToGetCellRenderer());

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        resultsPanel.add(tableScrollPane, BorderLayout.CENTER);
        mainSplit.setTopComponent(resultsPanel);

        // Bottom Panel: 50/50 comparison viewer (Left: Baseline POST, Right: Mutated GET)
        if (api != null && api.userInterface() != null) {
            baselineReqEditor = api.userInterface().createHttpRequestEditor();
            baselineRespEditor = api.userInterface().createHttpResponseEditor();
            mutatedReqEditor = api.userInterface().createHttpRequestEditor();
            mutatedRespEditor = api.userInterface().createHttpResponseEditor();
        }

        baselineTabbedPane = new JTabbedPane();
        baselineTabbedPane.setBorder(BorderFactory.createTitledBorder("Baseline (POST)"));
        if (baselineReqEditor != null && baselineRespEditor != null) {
            baselineTabbedPane.addTab("Request", baselineReqEditor.uiComponent());
            baselineTabbedPane.addTab("Response", baselineRespEditor.uiComponent());
        }

        mutatedTabbedPane = new JTabbedPane();
        mutatedTabbedPane.setBorder(BorderFactory.createTitledBorder("Mutated (GET with Query Params)"));
        if (mutatedReqEditor != null && mutatedRespEditor != null) {
            mutatedTabbedPane.addTab("Request", mutatedReqEditor.uiComponent());
            mutatedTabbedPane.addTab("Response", mutatedRespEditor.uiComponent());
        }

        JSplitPane compareSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, baselineTabbedPane, mutatedTabbedPane);
        compareSplitPane.setResizeWeight(0.5d);
        compareSplitPane.setDividerSize(6);

        mainSplit.setBottomComponent(compareSplitPane);
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
            for (PostToGetRun_littlespidy r : savedRuns) {
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

    private void loadRun(PostToGetRun_littlespidy run) {
        currentRun = run;
        currentResults.clear();
        if (run != null) {
            currentResults.addAll(run.getResults());
        }
        tableModel.fireTableDataChanged();

        for (PostToGetTestResult_littlespidy r : currentResults) {
            if (methodFilterDropDown != null && r.getMutatedMethod() != null) {
                methodFilterDropDown.registerMethod(r.getMutatedMethod());
            }
            if (statusCodeFilterDropDown != null && r.getMutatedStatusCode() > 0) {
                statusCodeFilterDropDown.registerStatusCode(r.getMutatedStatusCode());
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
            for (PostToGetRun_littlespidy r : savedRuns) {
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

        RowFilter<PostToGetResultsTableModel, Integer> filter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends PostToGetResultsTableModel, ? extends Integer> entry) {
                int rowIdx = entry.getIdentifier();
                if (rowIdx < 0 || rowIdx >= currentResults.size()) return false;
                PostToGetTestResult_littlespidy res = currentResults.get(rowIdx);

                if (methodFilterDropDown != null && !methodFilterDropDown.isMethodSelected(res.getMutatedMethod())) {
                    return false;
                }
                if (statusCodeFilterDropDown != null && !statusCodeFilterDropDown.isStatusCodeSelected(res.getMutatedStatusCode())) {
                    return false;
                }
                return true;
            }
        };
        tableSorter.setRowFilter(filter);
    }

    private void displayResultDetails(PostToGetTestResult_littlespidy result) {
        if (result == null) {
            clearEditors();
            return;
        }

        HttpRequest baseReq = null;
        HttpResponse baseResp = null;
        HttpRequest mutReq = null;
        HttpResponse mutResp = null;

        if (result.getOriginalReqResp() != null) {
            baseReq = result.getOriginalReqResp().request();
            if (result.getOriginalReqResp().hasResponse()) {
                baseResp = result.getOriginalReqResp().response();
            }
        } else {
            if (result.getOriginalRequestBytes() != null && result.getOriginalRequestBytes().length > 0) {
                baseReq = HttpRequest.httpRequest(ByteArray.byteArray(result.getOriginalRequestBytes()));
            }
            if (result.getOriginalResponseBytes() != null && result.getOriginalResponseBytes().length > 0) {
                baseResp = HttpResponse.httpResponse(ByteArray.byteArray(result.getOriginalResponseBytes()));
            }
        }

        if (result.getMutatedReqResp() != null) {
            mutReq = result.getMutatedReqResp().request();
            if (result.getMutatedReqResp().hasResponse()) {
                mutResp = result.getMutatedReqResp().response();
            }
        } else {
            if (result.getMutatedRequestBytes() != null && result.getMutatedRequestBytes().length > 0) {
                mutReq = HttpRequest.httpRequest(ByteArray.byteArray(result.getMutatedRequestBytes()));
            }
            if (result.getMutatedResponseBytes() != null && result.getMutatedResponseBytes().length > 0) {
                mutResp = HttpResponse.httpResponse(ByteArray.byteArray(result.getMutatedResponseBytes()));
            }
        }

        if (baselineReqEditor != null) baselineReqEditor.setRequest(baseReq);
        if (baselineRespEditor != null) baselineRespEditor.setResponse(baseResp);
        if (mutatedReqEditor != null) mutatedReqEditor.setRequest(mutReq);
        if (mutatedRespEditor != null) mutatedRespEditor.setResponse(mutResp);
    }

    private void clearEditors() {
        if (baselineReqEditor != null) baselineReqEditor.setRequest(null);
        if (baselineRespEditor != null) baselineRespEditor.setResponse(null);
        if (mutatedReqEditor != null) mutatedReqEditor.setRequest(null);
        if (mutatedRespEditor != null) mutatedRespEditor.setResponse(null);
    }

    private void updateSummary() {
        int total = currentResults.size();
        int accepted = 0;
        for (PostToGetTestResult_littlespidy r : currentResults) {
            if (r.getMutatedStatusCode() >= 200 && r.getMutatedStatusCode() < 300) {
                accepted++;
            }
        }
        statusSummaryLabel.setText(String.format("Status: Ready | Total: %d | GET Accepted: %d", total, accepted));
    }

    public void executeAttack(
            List<? extends EndpointSelectionItem_littlespidy> endpoints,
            String defaultTargetBaseUrl,
            AuthProfile_littlespidy profile,
            String customAuthHeader,
            int threads,
            int delayMs,
            String runnerName) {

        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "POST to GET Runner " + (++runnerCounter);
        currentRunName = name;
        PostToGetRun_littlespidy newRun = new PostToGetRun_littlespidy(name, new ArrayList<>());
        savedRuns.add(newRun);
        loadRun(newRun);
        updateRunnerCombo();

        engine.executeEndpointsTestsAsync(
                endpoints,
                defaultTargetBaseUrl,
                profile,
                customAuthHeader,
                threads,
                delayMs,
                new PostToGetProgressListener_littlespidy() {
                    @Override
                    public void onPostToGetTestCompleted(PostToGetTestResult_littlespidy result) {
                        SwingUtilities.invokeLater(() -> {
                            currentResults.add(result);
                            newRun.addResult(result);
                            if (methodFilterDropDown != null && result.getMutatedMethod() != null) {
                                methodFilterDropDown.registerMethod(result.getMutatedMethod());
                            }
                            if (statusCodeFilterDropDown != null && result.getMutatedStatusCode() > 0) {
                                statusCodeFilterDropDown.registerStatusCode(result.getMutatedStatusCode());
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
                                configPanel.onAttackFinished(engine.isCancelled(), currentResults.size());
                            }
                            notifyStateChanged();
                        });
                    }
                }
        );
    }

    public void executeAttack(HttpRequest postRequest, int threads, int delayMs, String runnerName) {
        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "POST to GET Runner " + (++runnerCounter);
        currentRunName = name;
        PostToGetRun_littlespidy newRun = new PostToGetRun_littlespidy(name, new ArrayList<>());
        savedRuns.add(newRun);
        loadRun(newRun);
        updateRunnerCombo();

        engine.executeRequestTestAsync(
                postRequest,
                threads,
                delayMs,
                new PostToGetProgressListener_littlespidy() {
                    @Override
                    public void onPostToGetTestCompleted(PostToGetTestResult_littlespidy result) {
                        SwingUtilities.invokeLater(() -> {
                            currentResults.add(result);
                            newRun.addResult(result);
                            if (methodFilterDropDown != null && result.getMutatedMethod() != null) {
                                methodFilterDropDown.registerMethod(result.getMutatedMethod());
                            }
                            if (statusCodeFilterDropDown != null && result.getMutatedStatusCode() > 0) {
                                statusCodeFilterDropDown.registerStatusCode(result.getMutatedStatusCode());
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
                                configPanel.onAttackFinished(engine.isCancelled(), currentResults.size());
                            }
                            notifyStateChanged();
                        });
                    }
                }
        );
    }

    public void sendToPostToGet(HttpRequest request, HttpResponse response) {
        if (request == null) return;
        String path = request.path() != null ? request.path() : "/";
        String runnerName = "POST to GET - " + path;
        executeAttack(request, 1, 50, runnerName);
    }

    private void exportToCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(currentRunName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_post_to_get_results.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Path,OriginalMethod,MutatedMethod,QueryParams,OriginalStatus,MutatedStatus,LengthDiff,Verdict\n");
                for (PostToGetTestResult_littlespidy r : currentResults) {
                    fw.write(String.format("\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"%d\",\"%s\"\n",
                            r.getId(), r.getPath(), r.getOriginalMethod(), r.getMutatedMethod(),
                            r.getConvertedQueryParams().replace("\"", "\"\""),
                            r.getOriginalStatusCode(), r.getMutatedStatusCode(),
                            (r.getMutatedResponseLength() - r.getOriginalResponseLength()),
                            r.getVerdict().replace("\"", "\"\"")));
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportToJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(currentRunName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_post_to_get_results.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("[\n");
                for (int i = 0; i < currentResults.size(); i++) {
                    PostToGetTestResult_littlespidy r = currentResults.get(i);
                    fw.write(String.format("  {\"id\": %d, \"path\": \"%s\", \"originalMethod\": \"%s\", \"mutatedMethod\": \"%s\", \"queryParams\": \"%s\", \"originalStatus\": %d, \"mutatedStatus\": %d, \"verdict\": \"%s\"}%s\n",
                            r.getId(), r.getPath(), r.getOriginalMethod(), r.getMutatedMethod(),
                            r.getConvertedQueryParams().replace("\"", "\\\""),
                            r.getOriginalStatusCode(), r.getMutatedStatusCode(),
                            r.getVerdict().replace("\"", "\\\""),
                            (i < currentResults.size() - 1 ? "," : "")));
                }
                fw.write("]\n");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public List<PostToGetRun_littlespidy> getSavedRuns() {
        return new ArrayList<>(savedRuns);
    }

    public void setSavedRuns(List<PostToGetRun_littlespidy> runs, String selectedRunnerId, int counter) {
        savedRuns.clear();
        if (runs != null) {
            savedRuns.addAll(runs);
        }
        this.runnerCounter = Math.max(counter, savedRuns.size() + 1);

        PostToGetRun_littlespidy toSelect = null;
        if (selectedRunnerId != null) {
            for (PostToGetRun_littlespidy r : savedRuns) {
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
        currentRun = new PostToGetRun_littlespidy("POST to GET Runner 1", new ArrayList<>());
        savedRuns.add(currentRun);
        loadRun(currentRun);
        updateRunnerCombo();
    }

    // Results Table Model
    private class PostToGetResultsTableModel extends AbstractTableModel {
        private final String[] columns = {"ID", "Endpoint Path", "Original Method", "Mutated Method", "Query Parameters", "Original Status", "Mutated Status", "Length Diff", "Verdict"};

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
            if (col == 0 || col == 5 || col == 6 || col == 7) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= currentResults.size()) return "";
            PostToGetTestResult_littlespidy r = currentResults.get(rowIndex);
            switch (columnIndex) {
                case 0: return r.getId();
                case 1: return r.getPath();
                case 2: return r.getOriginalMethod();
                case 3: return r.getMutatedMethod();
                case 4: return r.getConvertedQueryParams();
                case 5: return r.getOriginalStatusCode();
                case 6: return r.getMutatedStatusCode();
                case 7: return (r.getMutatedResponseLength() - r.getOriginalResponseLength());
                case 8: return r.getVerdict();
                default: return "";
            }
        }
    }

    private static class PostToGetCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (!isSelected) {
                int modelRow = table.convertRowIndexToModel(row);
                PostToGetTab_littlespidy tab = (PostToGetTab_littlespidy) SwingUtilities.getAncestorOfClass(PostToGetTab_littlespidy.class, table);
                if (tab != null && modelRow >= 0 && modelRow < tab.currentResults.size()) {
                    PostToGetTestResult_littlespidy r = tab.currentResults.get(modelRow);
                    if (r.getMutatedStatusCode() >= 200 && r.getMutatedStatusCode() < 300) {
                        c.setBackground(new Color(255, 230, 230)); // Highlight method tampering acceptance
                    } else if (r.getMutatedStatusCode() == 405) {
                        c.setBackground(new Color(230, 255, 230)); // Protected
                    } else {
                        c.setBackground(table.getBackground());
                    }
                }
            }
            return c;
        }
    }
}
