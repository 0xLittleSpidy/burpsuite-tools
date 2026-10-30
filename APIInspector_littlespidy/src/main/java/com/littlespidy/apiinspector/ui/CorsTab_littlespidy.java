// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.apiinspector.engine.CorsEngine_littlespidy;
import com.littlespidy.apiinspector.engine.CorsProgressListener_littlespidy;
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
 * Root Suite Tab for CORS Analysis and Testing.
 * Features:
 * Top: Runner dropdown with in-place rename, Delete Runner, Method filter,
 * dynamic Status Code multi-select dropdown, CORS Outcome filter, CSV/JSON export, and Clear.
 * Center: Sortable Results table (ID, Method, Host, Path, Tested Origin, Status Code, ACAO, ACAC, Description).
 * Bottom: 50/50 parallel side-by-side Montoya Request and Response editors.
 */
public class CorsTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final CorsEngine_littlespidy corsEngine;
    private CorsConfigPanel_littlespidy configPanel;
    private final List<Runnable> stateChangedListeners = new ArrayList<>();

    // Runner History Management
    private final List<CorsRun_littlespidy> savedRuns = new ArrayList<>();
    private CorsRun_littlespidy currentRun;
    private int runnerCounter = 1;
    private String currentRunName = "CORS Runner 1";
    private JComboBox<String> runnerCombo;
    private boolean updatingRunnerCombo = false;
    private JButton deleteRunnerBtn;

    // Filters UI
    private MethodFilterDropDown_littlespidy methodFilterDropDown;
    private StatusCodeFilterDropDown_littlespidy statusCodeFilterDropDown;
    private CorsOutcomeFilterDropDown_littlespidy outcomeFilterDropDown;

    // Results UI
    private final List<CorsTestResult_littlespidy> currentResults = new ArrayList<>();
    private final CorsResultsTableModel tableModel = new CorsResultsTableModel();
    private final JTable resultsTable = new JTable(tableModel);
    private TableRowSorter<CorsResultsTableModel> tableSorter;

    // Editors UI (50/50 Split)
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    private final JLabel statusSummaryLabel = new JLabel("Status: Ready | Total: 0");

    public CorsTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.corsEngine = new CorsEngine_littlespidy(api);

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();

        // Initial default runner
        currentRun = new CorsRun_littlespidy(currentRunName, new ArrayList<>());
        savedRuns.add(currentRun);
        updateRunnerCombo();
    }

    public CorsEngine_littlespidy getCorsEngine() {
        return corsEngine;
    }

    public void setConfigPanel(CorsConfigPanel_littlespidy configPanel) {
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
        resultsPanel.setBorder(new TitledBorder("CORS Test Results"));

        // Results Filter Bar located above results table
        JPanel resultsFilterBar = new JPanel(new BorderLayout(6, 2));
        JPanel leftFilter = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        leftFilter.add(new JLabel("Runner:"));
        runnerCombo = new JComboBox<>();
        runnerCombo.setEditable(true);
        runnerCombo.setPreferredSize(new Dimension(170, 24));
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

        outcomeFilterDropDown = new CorsOutcomeFilterDropDown_littlespidy();
        outcomeFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(outcomeFilterDropDown);

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

        resultsTable.setDefaultRenderer(Object.class, new CorsCellRenderer());

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        resultsPanel.add(tableScrollPane, BorderLayout.CENTER);
        mainSplit.setTopComponent(resultsPanel);

        // Bottom Panel: 50/50 parallel side-by-side Montoya Request and Response editors
        if (api != null && api.userInterface() != null) {
            requestEditor = api.userInterface().createHttpRequestEditor();
            responseEditor = api.userInterface().createHttpResponseEditor();
        }

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request Viewer (Tested Origin)"));
        if (requestEditor != null) {
            requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        } else {
            requestPanel.add(new JScrollPane(new JTextArea("Montoya HttpRequestEditor placeholder")), BorderLayout.CENTER);
        }

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response Viewer (CORS Headers)"));
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
            for (CorsRun_littlespidy r : savedRuns) {
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

    private void loadRun(CorsRun_littlespidy run) {
        currentRun = run;
        currentResults.clear();
        if (run != null) {
            currentResults.addAll(run.getResults());
        }
        tableModel.fireTableDataChanged();

        for (CorsTestResult_littlespidy r : currentResults) {
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
            for (CorsRun_littlespidy r : savedRuns) {
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

        RowFilter<CorsResultsTableModel, Integer> filter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends CorsResultsTableModel, ? extends Integer> entry) {
                int rowIdx = entry.getIdentifier();
                if (rowIdx < 0 || rowIdx >= currentResults.size()) return false;
                CorsTestResult_littlespidy res = currentResults.get(rowIdx);

                if (methodFilterDropDown != null && !methodFilterDropDown.isMethodSelected(res.getMethod())) {
                    return false;
                }
                if (statusCodeFilterDropDown != null && !statusCodeFilterDropDown.isStatusCodeSelected(res.getStatusCode())) {
                    return false;
                }
                if (outcomeFilterDropDown != null && !outcomeFilterDropDown.matches(res)) {
                    return false;
                }
                return true;
            }
        };
        tableSorter.setRowFilter(filter);
    }

    private void displayResultDetails(CorsTestResult_littlespidy result) {
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
        int reflected = 0;
        int acac = 0;
        for (CorsTestResult_littlespidy r : currentResults) {
            if (r.getReflectedAcao() != null && !r.getReflectedAcao().isBlank()) reflected++;
            if (r.isAcacPresent()) acac++;
        }
        statusSummaryLabel.setText(String.format("Status: Ready | Total: %d | Reflected: %d | ACAC: %d",
                total, reflected, acac));
    }

    public void executeAttack(
            List<? extends EndpointSelectionItem_littlespidy> endpoints,
            String targetBaseUrl,
            String attackerDomain,
            AuthProfile_littlespidy profile,
            String customAuthHeader,
            List<CorsTechnique_littlespidy> techniques,
            int threads,
            int delayMs,
            String runnerName) {

        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "CORS Runner " + (++runnerCounter);
        currentRunName = name;
        CorsRun_littlespidy newRun = new CorsRun_littlespidy(name, new ArrayList<>());
        savedRuns.add(newRun);
        loadRun(newRun);
        updateRunnerCombo();

        corsEngine.executeEndpointsTestsAsync(
                endpoints,
                targetBaseUrl,
                attackerDomain,
                profile,
                customAuthHeader,
                techniques,
                threads,
                delayMs,
                new CorsProgressListener_littlespidy() {
                    @Override
                    public void onCorsTestCompleted(CorsTestResult_littlespidy result) {
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
                                configPanel.onAttackFinished(corsEngine.isCancelled(), currentResults.size());
                            }
                            notifyStateChanged();
                        });
                    }
                }
        );
    }

    public void executeAttack(
            HttpRequest targetRequest,
            String targetBaseUrl,
            String attackerDomain,
            AuthProfile_littlespidy profile,
            String customAuthHeader,
            List<CorsTechnique_littlespidy> techniques,
            int threads,
            int delayMs,
            String runnerName) {

        String name = (runnerName != null && !runnerName.isBlank()) ? runnerName : "CORS Runner " + (++runnerCounter);
        currentRunName = name;
        CorsRun_littlespidy newRun = new CorsRun_littlespidy(name, new ArrayList<>());
        savedRuns.add(newRun);
        loadRun(newRun);
        updateRunnerCombo();

        corsEngine.executeTestsAsync(
                targetRequest,
                targetBaseUrl,
                attackerDomain,
                profile,
                customAuthHeader,
                techniques,
                threads,
                delayMs,
                new CorsProgressListener_littlespidy() {
                    @Override
                    public void onCorsTestCompleted(CorsTestResult_littlespidy result) {
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
                                configPanel.onAttackFinished(corsEngine.isCancelled(), currentResults.size());
                            }
                            notifyStateChanged();
                        });
                    }
                }
        );
    }

    public void executeAttack(
            HttpRequest targetRequest,
            String targetBaseUrl,
            String attackerDomain,
            List<CorsTechnique_littlespidy> techniques,
            int threads,
            int delayMs,
            String runnerName) {
        executeAttack(targetRequest, targetBaseUrl, attackerDomain, null, null, techniques, threads, delayMs, runnerName);
    }

    public void sendToCors(HttpRequest request, HttpResponse response) {
        if (request == null) return;
        String host = request.httpService() != null ? request.httpService().host() : "target";
        String runnerName = "CORS - " + host;

        List<CorsTechnique_littlespidy> techs = CorsTechnique_littlespidy.getDefaultTechniques();
        String targetUrl = request.url();
        String attacker = "evil.com";

        executeAttack(request, targetUrl, attacker, techs, 4, 50, runnerName);
    }

    private void exportToCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(currentRunName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_cors_results.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("ID,Method,Host,Path,TestedOrigin,Status,ACAO,ACAC,Description\n");
                for (CorsTestResult_littlespidy r : currentResults) {
                    fw.write(String.format("\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%s\",\"%s\",\"%s\"\n",
                            r.getId(), r.getMethod(), r.getHost(), r.getPath(), r.getTestedOrigin(),
                            r.getStatusCode(), r.getReflectedAcao(), r.isAcacPresent(),
                            r.getDescription().replace("\"", "\"\"")));
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportToJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(currentRunName.replaceAll("[^a-zA-Z0-9_-]", "_") + "_cors_results.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("[\n");
                for (int i = 0; i < currentResults.size(); i++) {
                    CorsTestResult_littlespidy r = currentResults.get(i);
                    fw.write(String.format("  {\"id\": %d, \"method\": \"%s\", \"host\": \"%s\", \"path\": \"%s\", \"testedOrigin\": \"%s\", \"status\": %d, \"acao\": \"%s\", \"acac\": %b}%s\n",
                            r.getId(), r.getMethod(), r.getHost(), r.getPath(), r.getTestedOrigin(),
                            r.getStatusCode(), r.getReflectedAcao(), r.isAcacPresent(),
                            (i < currentResults.size() - 1 ? "," : "")));
                }
                fw.write("]\n");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public List<CorsRun_littlespidy> getSavedRuns() {
        return new ArrayList<>(savedRuns);
    }

    public void setSavedRuns(List<CorsRun_littlespidy> runs, String selectedRunnerId, int counter) {
        savedRuns.clear();
        if (runs != null) {
            savedRuns.addAll(runs);
        }
        this.runnerCounter = Math.max(counter, savedRuns.size() + 1);

        CorsRun_littlespidy toSelect = null;
        if (selectedRunnerId != null) {
            for (CorsRun_littlespidy r : savedRuns) {
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
        currentRun = new CorsRun_littlespidy("CORS Runner 1", new ArrayList<>());
        savedRuns.add(currentRun);
        loadRun(currentRun);
        updateRunnerCombo();
    }

    // Results Table Model (Columns: ID, Method, Host, Path, Tested Origin, Status Code, ACAO, ACAC, Description)
    private class CorsResultsTableModel extends AbstractTableModel {
        private final String[] columns = {"ID", "Method", "Host", "Path", "Tested Origin", "Status Code", "ACAO", "ACAC", "Description"};

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
            if (col == 0 || col == 5) return Integer.class;
            if (col == 7) return Boolean.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= currentResults.size()) return "";
            CorsTestResult_littlespidy r = currentResults.get(rowIndex);
            switch (columnIndex) {
                case 0: return r.getId();
                case 1: return r.getMethod();
                case 2: return r.getHost();
                case 3: return r.getPath();
                case 4: return r.getTestedOrigin();
                case 5: return r.getStatusCode();
                case 6: return r.getReflectedAcao();
                case 7: return r.isAcacPresent();
                case 8: return r.getDescription();
                default: return "";
            }
        }
    }

    private static class CorsCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (!isSelected) {
                int modelRow = table.convertRowIndexToModel(row);
                CorsTab_littlespidy tab = (CorsTab_littlespidy) SwingUtilities.getAncestorOfClass(CorsTab_littlespidy.class, table);
                if (tab != null && modelRow >= 0 && modelRow < tab.currentResults.size()) {
                    CorsTestResult_littlespidy r = tab.currentResults.get(modelRow);
                    if (r.isAcacPresent() && r.getReflectedAcao() != null && !r.getReflectedAcao().isBlank()) {
                        c.setBackground(new Color(255, 230, 230)); // Highlight potential exploit
                    } else if (r.getReflectedAcao() != null && !r.getReflectedAcao().isBlank()) {
                        c.setBackground(new Color(255, 248, 220)); // Highlight reflection
                    } else {
                        c.setBackground(table.getBackground());
                    }
                }
            }
            return c;
        }
    }
}
