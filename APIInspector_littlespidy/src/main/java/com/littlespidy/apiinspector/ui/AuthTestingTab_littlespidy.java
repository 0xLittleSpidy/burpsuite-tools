// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy;
import com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy.EndpointTestTarget;
import com.littlespidy.apiinspector.engine.AuthTestProgressListener_littlespidy;
import com.littlespidy.apiinspector.model.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * Tab for configuring authentication profiles, executing automated authentication/authorization
 * test suites across imported API collections, and inspecting comparative results.
 * Follows the architecture, component structure, and design patterns of ng-auth-analyzer_littlespidy.
 */
public class AuthTestingTab_littlespidy extends JPanel implements AuthTestProgressListener_littlespidy {

    private final MontoyaApi api;
    private final AuthTestEngine_littlespidy testEngine;
    private AuthAnalyzerConfigTab_littlespidy configTab;
    private final List<AuthProfile_littlespidy> profiles = new ArrayList<>();
    private final Set<String> activeProfileIds = new HashSet<>();
    private final List<AuthTestResult_littlespidy> results = new ArrayList<>();

    private APIImportTab_littlespidy importTabRef;
    private final List<Runnable> stateChangedListeners = new ArrayList<>();

    // Results UI
    private ResultsTableModel resultsTableModel;
    private JTable resultsTable;
    private TableRowSorter<ResultsTableModel> resultsSorter;
    private MethodFilterDropDown_littlespidy methodFilterDropDown;
    private ProfileStatusFilterDropDown_littlespidy statusFilterDropDown;
    private ClassificationFilterDropDown_littlespidy classificationFilterDropDown;
    private JButton deleteRunnerBtn;

    // Per-profile columns and endpoint-based result rows matching ng-auth-analyzer_littlespidy
    private final List<EndpointResultRow_littlespidy> endpointRows = new ArrayList<>();
    private final List<ProfileColumnDef_littlespidy> displayedProfiles = new ArrayList<>();

    // Runner History Management
    private final List<AuthTestRun_littlespidy> savedRuns = new ArrayList<>();
    private AuthTestRun_littlespidy currentRun;
    private int runnerCounter = 1;
    private String currentRunName = "Runner 1";
    private JComboBox<String> runnerCombo;
    private boolean updatingRunnerCombo = false;

    // HTTP Message Inspector (Compare View)
    private JToggleButton requestToggleButton;
    private JToggleButton responseToggleButton;
    private int activeInspectorViewMode = 0; // 0 = Request, 1 = Response
    private JPanel columnsContainer;
    private JScrollPane columnsScrollPane;
    private final List<ProfileColumnView> columnViews = new ArrayList<>();

    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public AuthTestingTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.testEngine = new AuthTestEngine_littlespidy(api != null ? api.http() : null);

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    public void setConfigTab(AuthAnalyzerConfigTab_littlespidy configTab) {
        this.configTab = configTab;
        if (configTab != null && !profiles.isEmpty()) {
            configTab.setProfiles(profiles);
        }
    }

    public AuthAnalyzerConfigTab_littlespidy getConfigTab() {
        return configTab;
    }

    public void onProfilesUpdated() {
        rebuildModel();
    }

    public void setImportTabRef(APIImportTab_littlespidy importTabRef) {
        this.importTabRef = importTabRef;
        if (configTab != null) {
            configTab.setImportTabRef(importTabRef);
        }
    }

    public void addStateChangedListener(Runnable listener) {
        if (listener != null) {
            this.stateChangedListeners.add(listener);
        }
    }

    public void setOnStateChangedCallback(Runnable callback) {
        if (callback != null) {
            this.stateChangedListeners.add(callback);
        }
    }

    private void notifyStateChanged() {
        for (Runnable r : new ArrayList<>(stateChangedListeners)) {
            try {
                r.run();
            } catch (Exception ignored) {
            }
        }
        if (importTabRef != null) {
            importTabRef.updateAvailableProfiles(getAllProfiles());
        }
    }

    private void initComponents() {
        // --- Dedicated Attack & Results View: Results Table & Side-by-Side HTTP Message Inspector ---
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.50);
        mainSplit.setContinuousLayout(true);

        // Top: Results Table
        JPanel resultsPanel = new JPanel(new BorderLayout(4, 4));
        resultsPanel.setBorder(new TitledBorder("Authentication Test Results"));

        // Results Filter Bar located above results table
        JPanel resultsFilterBar = new JPanel(new BorderLayout(6, 2));
        JPanel leftFilter = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        leftFilter.add(new JLabel("Runner:"));
        runnerCombo = new JComboBox<>();
        runnerCombo.setPreferredSize(new Dimension(160, 24));
        runnerCombo.setToolTipText("Select a test runner to inspect its results");
        runnerCombo.addActionListener(e -> onRunnerSelected());
        leftFilter.add(runnerCombo);

        deleteRunnerBtn = new JButton("Delete Runner");
        deleteRunnerBtn.setToolTipText("Delete the currently selected runner from history");
        deleteRunnerBtn.addActionListener(e -> onDeleteCurrentRunner());
        leftFilter.add(deleteRunnerBtn);

        methodFilterDropDown = new MethodFilterDropDown_littlespidy();
        methodFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(methodFilterDropDown);

        statusFilterDropDown = new ProfileStatusFilterDropDown_littlespidy();
        statusFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(statusFilterDropDown);

        classificationFilterDropDown = new ClassificationFilterDropDown_littlespidy();
        classificationFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(classificationFilterDropDown);

        resultsFilterBar.add(leftFilter, BorderLayout.WEST);

        JPanel rightResultsActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton retryFailedBtn = new JButton("Retry Failed");
        retryFailedBtn.addActionListener(e -> onRetryFailed());
        JButton exportCsvBtn = new JButton("Export CSV");
        exportCsvBtn.addActionListener(e -> onExportCsv());
        JButton exportJsonBtn = new JButton("Export JSON");
        exportJsonBtn.addActionListener(e -> onExportJson());
        JButton clearResultsBtn = new JButton("Clear Results");
        clearResultsBtn.addActionListener(e -> onClearResults());

        rightResultsActions.add(retryFailedBtn);
        rightResultsActions.add(exportCsvBtn);
        rightResultsActions.add(exportJsonBtn);
        rightResultsActions.add(clearResultsBtn);
        resultsFilterBar.add(rightResultsActions, BorderLayout.EAST);
        resultsPanel.add(resultsFilterBar, BorderLayout.NORTH);

        resultsTableModel = new ResultsTableModel();
        resultsTable = new JTable(resultsTableModel) {
            private static final long serialVersionUID = 1L;

            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                boolean isSelected = isRowSelected(row);
                int modelRow = convertRowIndexToModel(row);
                String cl = (modelRow >= 0 && modelRow < endpointRows.size())
                        ? endpointRows.get(modelRow).getClassification()
                        : null;

                if (isSelected) {
                    c.setBackground(getSelectionBackground());
                    c.setForeground(getSelectionForeground());
                } else {
                    if ("TRUE_POSITIVE".equalsIgnoreCase(cl)) {
                        c.setBackground(new Color(220, 248, 224));
                        c.setForeground(new Color(0, 100, 0));
                    } else if ("FALSE_POSITIVE".equalsIgnoreCase(cl)) {
                        c.setBackground(new Color(255, 230, 230));
                        c.setForeground(new Color(160, 0, 0));
                    } else {
                        c.setBackground(getBackground());
                        c.setForeground(getForeground());
                    }
                }
                return c;
            }
        };
        resultsSorter = new TableRowSorter<>(resultsTableModel);
        resultsTable.setRowSorter(resultsSorter);
        resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onResultRowSelected();
            }
        });

        // Context Menu for Marking True Positive / False Positive
        JPopupMenu resultsContextMenu = new JPopupMenu();
        JMenuItem tpItem = new JMenuItem("Mark as True Positive");
        tpItem.addActionListener(e -> setMarkOnSelectedRows("TRUE_POSITIVE"));
        JMenuItem fpItem = new JMenuItem("Mark as False Positive");
        fpItem.addActionListener(e -> setMarkOnSelectedRows("FALSE_POSITIVE"));
        JMenuItem clearItem = new JMenuItem("Clear Classification");
        clearItem.addActionListener(e -> setMarkOnSelectedRows(null));

        resultsContextMenu.add(tpItem);
        resultsContextMenu.add(fpItem);
        resultsContextMenu.addSeparator();
        resultsContextMenu.add(clearItem);

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = resultsTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        boolean alreadySelected = false;
                        for (int sel : resultsTable.getSelectedRows()) {
                            if (sel == row) {
                                alreadySelected = true;
                                break;
                            }
                        }
                        if (!alreadySelected) {
                            resultsTable.setRowSelectionInterval(row, row);
                        }
                        resultsContextMenu.show(resultsTable, e.getX(), e.getY());
                    }
                }
            }
        });

        JScrollPane resScroll = new JScrollPane(resultsTable);
        resultsPanel.add(resScroll, BorderLayout.CENTER);
        mainSplit.setTopComponent(resultsPanel);

        // Bottom: Multi-Column Compare Viewer
        JPanel messageViewHeaderPanel = new JPanel(new BorderLayout());

        JPanel leftSwitchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        ButtonGroup viewGroup = new ButtonGroup();
        requestToggleButton = new JToggleButton("Request");
        responseToggleButton = new JToggleButton("Response");
        viewGroup.add(requestToggleButton);
        viewGroup.add(responseToggleButton);
        requestToggleButton.setSelected(true);
        requestToggleButton.addActionListener(e -> setInspectorViewMode(0));
        responseToggleButton.addActionListener(e -> setInspectorViewMode(1));

        leftSwitchPanel.add(requestToggleButton);
        leftSwitchPanel.add(responseToggleButton);

        messageViewHeaderPanel.add(leftSwitchPanel, BorderLayout.WEST);

        columnsContainer = new JPanel(new GridLayout(1, 0, 8, 0)) {
            private static final long serialVersionUID = 1L;
            @Override
            public Dimension getPreferredSize() {
                int colCount = Math.max(1, getComponentCount());
                int minWidth = colCount * 360;
                int viewWidth = columnsScrollPane != null && columnsScrollPane.getViewport() != null ?
                        columnsScrollPane.getViewport().getWidth() : 0;
                int w = Math.max(minWidth, viewWidth);
                int h = columnsScrollPane != null && columnsScrollPane.getViewport() != null ?
                        Math.max(200, columnsScrollPane.getViewport().getHeight()) : 200;
                return new Dimension(w, h);
            }
        };

        columnsScrollPane = new JScrollPane(columnsContainer, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        columnsScrollPane.getHorizontalScrollBar().setUnitIncrement(16);

        JPanel inspectorPanel = new JPanel(new BorderLayout());
        inspectorPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        inspectorPanel.add(messageViewHeaderPanel, BorderLayout.NORTH);
        inspectorPanel.add(columnsScrollPane, BorderLayout.CENTER);

        mainSplit.setBottomComponent(inspectorPanel);
        add(mainSplit, BorderLayout.CENTER);
    }

    public void setInspectorViewMode(int mode) {
        this.activeInspectorViewMode = mode;
        if (mode == 0) {
            requestToggleButton.setSelected(true);
        } else {
            responseToggleButton.setSelected(true);
        }
        for (ProfileColumnView view : columnViews) {
            view.setViewMode(mode);
        }
        if (columnsContainer != null) {
            columnsContainer.revalidate();
            columnsContainer.repaint();
        }
    }

    // --- Attack Execution Actions ---

    public void startAttackExecution(
            List<AuthAnalyzerConfigTab_littlespidy.EndpointSelectionItem> items,
            List<AuthProfile_littlespidy> activeProfiles,
            String runnerName,
            int threads,
            int delay) {
        if (items.isEmpty() || activeProfiles.isEmpty()) return;

        List<EndpointTestTarget> targets = new ArrayList<>();
        for (AuthAnalyzerConfigTab_littlespidy.EndpointSelectionItem it : items) {
            for (AuthProfile_littlespidy p : activeProfiles) {
                targets.add(new EndpointTestTarget(it.collection, it.endpoint, p));
            }
        }

        currentRunName = (runnerName != null && !runnerName.trim().isEmpty())
                ? runnerName.trim()
                : ("Runner " + getRunnerCounter());
        results.clear();
        endpointRows.clear();

        rebuildDisplayedProfiles();
        resultsTableModel.fireTableStructureChanged();

        setExecutionUIState(true);
        testEngine.startTesting(targets, threads, delay, false, this);
    }

    public void cancelAttack() {
        testEngine.stopTesting();
        setExecutionUIState(false);
    }

    private void onCancelRun() {
        cancelAttack();
    }

    private void onRetryFailed() {
        List<EndpointTestTarget> targetsToRetry = new ArrayList<>();
        for (AuthTestResult_littlespidy res : results) {
            if (res.getOutcome() == AuthTestOutcome_littlespidy.NETWORK_ERROR
                    || res.getOutcome() == AuthTestOutcome_littlespidy.SERVER_ERROR
                    || res.getAuthStatusCode() == 0) {

                ImportedCollection_littlespidy col = findCollectionById(res.getCollectionId());
                DiscoveredEndpoint_littlespidy ep = findEndpoint(col, res.getMethod(), res.getPath());
                if (col != null && ep != null) {
                    AuthProfile_littlespidy p = findProfileById(res.getProfileId());
                    targetsToRetry.add(new EndpointTestTarget(col, ep, p));
                }
            }
        }

        if (targetsToRetry.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No failed requests found to retry.", "Information", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int threads = configTab != null ? configTab.getThreadCount() : 4;
        int delay = configTab != null ? configTab.getDelayMs() : 50;

        setExecutionUIState(true);
        testEngine.startTesting(targetsToRetry, threads, delay, false, this);
    }

    private void onClearResults() {
        if (currentRun != null) {
            savedRuns.remove(currentRun);
            currentRun = null;
        }
        results.clear();
        rebuildModel();
        clearInspector();
        if (statusFilterDropDown != null) {
            statusFilterDropDown.updateOptions(results);
        }
        applyAllFilters();
        updateRunnerCombo();
        notifyStateChanged();
    }

    private void onDeleteCurrentRunner() {
        if (savedRuns.isEmpty() || runnerCombo == null) {
            return;
        }
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
            clearInspector();
            notifyStateChanged();
        }
    }

    private void onRunnerSelected() {
        if (updatingRunnerCombo || runnerCombo == null) return;
        int idx = runnerCombo.getSelectedIndex();
        if (idx >= 0 && idx < savedRuns.size()) {
            AuthTestRun_littlespidy run = savedRuns.get(idx);
            loadRun(run);
            notifyStateChanged();
        }
    }

    private void loadRun(AuthTestRun_littlespidy run) {
        currentRun = run;
        results.clear();
        endpointRows.clear();
        displayedProfiles.clear();
        if (run != null) {
            results.addAll(run.getResults());
            if (run.getEndpointRows().isEmpty() && !results.isEmpty()) {
                endpointRows.addAll(buildEndpointRows(results));
            } else {
                endpointRows.addAll(run.getEndpointRows());
            }
            if (run.getDisplayedProfiles().isEmpty()) {
                displayedProfiles.addAll(buildDisplayedProfiles(results, getAllProfiles(), getActiveProfileIds()));
            } else {
                displayedProfiles.addAll(buildDisplayedProfiles(results, getAllProfiles(), getActiveProfileIds()));
            }
        }
        resultsTableModel.fireTableStructureChanged();
        for (AuthTestResult_littlespidy r : results) {
            if (methodFilterDropDown != null && r.getMethod() != null) {
                methodFilterDropDown.registerMethod(r.getMethod());
            }
        }
        if (statusFilterDropDown != null) {
            statusFilterDropDown.updateOptions(results);
        }
        applyAllFilters();
        if (!endpointRows.isEmpty()) {
            resultsTable.setRowSelectionInterval(0, 0);
        } else {
            clearInspector();
        }
    }

    private void updateRunnerCombo() {
        if (runnerCombo == null) return;
        updatingRunnerCombo = true;
        try {
            runnerCombo.removeAllItems();
            for (AuthTestRun_littlespidy r : savedRuns) {
                runnerCombo.addItem(r.getName() + " (" + r.getResults().size() + " results)");
            }
            if (!savedRuns.isEmpty()) {
                runnerCombo.setSelectedIndex(savedRuns.size() - 1);
            }
        } finally {
            updatingRunnerCombo = false;
        }
    }

    private void setExecutionUIState(boolean running) {
        if (configTab != null) {
            configTab.setExecutionUIState(running);
        }
    }

    // --- Progress Listener Implementation ---

    @Override
    public void onTestStarted(int totalEndpoints) {
        SwingUtilities.invokeLater(() -> {
            if (configTab != null) {
                configTab.updateProgress(0, totalEndpoints, "");
            }
        });
    }

    @Override
    public void onEndpointResult(AuthTestResult_littlespidy result, int completedCount, int totalCount) {
        SwingUtilities.invokeLater(() -> {
            results.add(result);
            String key = (result.getCollectionId() != null ? result.getCollectionId() : "") + "::"
                    + (result.getMethod() != null ? result.getMethod().toUpperCase() : "") + "::"
                    + (result.getPath() != null ? result.getPath() : "");

            EndpointResultRow_littlespidy existingRow = null;
            int rowIndex = -1;
            for (int i = 0; i < endpointRows.size(); i++) {
                if (key.equals(endpointRows.get(i).getKey())) {
                    existingRow = endpointRows.get(i);
                    rowIndex = i;
                    break;
                }
            }

            String profileKey = resolveProfileKey(result);
            if (existingRow == null) {
                existingRow = new EndpointResultRow_littlespidy(
                        result.getCollectionId(), result.getCollectionName(), result.getMethod(), result.getPath()
                );
                existingRow.getProfileResults().put(profileKey, result);
                endpointRows.add(existingRow);
                resultsTableModel.fireTableRowsInserted(endpointRows.size() - 1, endpointRows.size() - 1);
            } else {
                existingRow.getProfileResults().put(profileKey, result);
                resultsTableModel.fireTableRowsUpdated(rowIndex, rowIndex);
            }

            if (configTab != null) {
                configTab.updateProgress(completedCount, totalCount, "");
            }
            if (methodFilterDropDown != null && result.getMethod() != null) {
                methodFilterDropDown.registerMethod(result.getMethod());
            }
            if (statusFilterDropDown != null) {
                statusFilterDropDown.updateOptions(results);
            }
            notifyStateChanged();
        });
    }

    @Override
    public void onTestError(String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            if (configTab != null) {
                configTab.onAttackError(errorMessage);
            }
        });
    }

    @Override
    public void onTestFinished(boolean cancelled, int totalCompleted) {
        SwingUtilities.invokeLater(() -> {
            setExecutionUIState(false);
            rebuildModel();
            AuthTestRun_littlespidy run = new AuthTestRun_littlespidy(currentRunName, results, endpointRows, displayedProfiles);
            savedRuns.add(run);
            currentRun = run;
            updateRunnerCombo();
            if (statusFilterDropDown != null) {
                statusFilterDropDown.updateOptions(results);
            }
            applyAllFilters();
            if (configTab != null) {
                configTab.onAttackFinished(cancelled, totalCompleted);
            } else {
                runnerCounter++;
            }
            notifyStateChanged();
        });
    }

    // --- Result Selection & Multi-Column Inspector Inspection ---

    private void onResultRowSelected() {
        int row = resultsTable.getSelectedRow();
        if (row < 0 || row >= endpointRows.size()) {
            clearInspector();
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(row);
        EndpointResultRow_littlespidy selectedEndpointRow = endpointRows.get(modelRow);

        columnsContainer.removeAll();
        columnViews.clear();

        // Populate side-by-side columns strictly according to the deterministic displayedProfiles order
        for (ProfileColumnDef_littlespidy def : displayedProfiles) {
            AuthTestResult_littlespidy r = selectedEndpointRow.getProfileResults().get(def.getId());
            if (r == null) {
                continue;
            }

            Component reqComp = null;
            Component respComp = null;

            if (api != null && api.userInterface() != null) {
                HttpRequestEditor reqEd = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
                if (r.getAuthRequestBytes() != null && r.getAuthRequestBytes().length > 0) {
                    reqEd.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(r.getAuthRequestBytes())));
                }
                reqComp = reqEd.uiComponent();

                HttpResponseEditor respEd = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
                if (r.getAuthResponseBytes() != null && r.getAuthResponseBytes().length > 0) {
                    respEd.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(r.getAuthResponseBytes())));
                }
                respComp = respEd.uiComponent();
            }

            int code = r.getAuthStatusCode();
            int len = r.getAuthResponseLength();
            String info = (code > 0 ? ("Status: " + code) : "Status: -") + " | " + (len >= 0 ? len + " B" : "-");

            Color colHeaderBg = null;
            if (code >= 200 && code < 300) {
                colHeaderBg = new Color(0, 255, 51, 60);
            } else if (code >= 400 && code < 500) {
                colHeaderBg = new Color(255, 153, 0, 60);
            } else if (code >= 500) {
                colHeaderBg = new Color(255, 51, 51, 60);
            } else {
                colHeaderBg = new Color(225, 238, 255);
            }

            String title = (r.getProfileName() != null && !r.getProfileName().isBlank())
                    ? r.getProfileName() : def.getDisplayName();
            ProfileColumnView colView = new ProfileColumnView(title, info, colHeaderBg, reqComp, respComp);
            colView.setViewMode(activeInspectorViewMode);
            columnViews.add(colView);
            columnsContainer.add(colView.panel);
        }

        columnsContainer.revalidate();
        columnsContainer.repaint();
    }

    private void clearInspector() {
        columnsContainer.removeAll();
        columnViews.clear();
        columnsContainer.revalidate();
        columnsContainer.repaint();
    }

    public void applyAllFilters() {
        if (resultsSorter == null) return;

        RowFilter<ResultsTableModel, Integer> filter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ResultsTableModel, ? extends Integer> entry) {
                int rowIdx = entry.getIdentifier();
                if (rowIdx < 0 || rowIdx >= endpointRows.size()) {
                    return false;
                }
                EndpointResultRow_littlespidy epRow = endpointRows.get(rowIdx);

                // 1. Dynamic HTTP Method filter
                if (methodFilterDropDown != null && !methodFilterDropDown.isMethodSelected(epRow.getMethod())) {
                    return false;
                }

                // 2. Profile - Status Code filter
                if (statusFilterDropDown != null && !statusFilterDropDown.matches(epRow)) {
                    return false;
                }

                // 3. Classification filter
                if (classificationFilterDropDown != null && !classificationFilterDropDown.matches(epRow)) {
                    return false;
                }

                return true;
            }
        };
        resultsSorter.setRowFilter(filter);
    }

    public void setMarkOnSelectedRows(String classification) {
        int[] selectedViewRows = resultsTable.getSelectedRows();
        if (selectedViewRows.length == 0) return;
        for (int vRow : selectedViewRows) {
            int mRow = resultsTable.convertRowIndexToModel(vRow);
            if (mRow >= 0 && mRow < endpointRows.size()) {
                EndpointResultRow_littlespidy epRow = endpointRows.get(mRow);
                epRow.setClassification(classification);
                for (AuthTestResult_littlespidy r : epRow.getProfileResults().values()) {
                    r.setClassification(classification);
                }
                for (AuthTestResult_littlespidy r : results) {
                    if (epRow.getKey().equals((r.getCollectionId() != null ? r.getCollectionId() : "") + "::"
                            + (r.getMethod() != null ? r.getMethod().toUpperCase() : "") + "::"
                            + (r.getPath() != null ? r.getPath() : ""))) {
                        r.setClassification(classification);
                    }
                }
            }
        }
        resultsTableModel.fireTableDataChanged();
        for (int vRow : selectedViewRows) {
            if (vRow >= 0 && vRow < resultsTable.getRowCount()) {
                resultsTable.addRowSelectionInterval(vRow, vRow);
            }
        }
        resultsTable.repaint();
        applyAllFilters();
        notifyStateChanged();
    }

    public void applyOutcomeFilter() {
        applyAllFilters();
    }

    // --- Export Actions ---

    private void onExportCsv() {
        if (results.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No test results to export.", "Information", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("api_auth_test_results.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(target)) {
                fw.write("Collection,Method,Path,FullUrl,Profile,StatusCode,Length,Outcome,Error\n");
                for (AuthTestResult_littlespidy r : results) {
                    fw.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,%d,\"%s\",\"%s\"\n",
                            escapeCsv(r.getCollectionName()),
                            escapeCsv(r.getMethod()),
                            escapeCsv(r.getPath()),
                            escapeCsv(r.getFullUrl()),
                            escapeCsv(r.getProfileName()),
                            r.getAuthStatusCode(),
                            r.getAuthResponseLength(),
                            r.getOutcome().name(),
                            escapeCsv(r.getErrorMessage())
                    ));
                }
                JOptionPane.showMessageDialog(this, "Exported " + results.size() + " results to " + target.getName(), "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error exporting CSV: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void onExportJson() {
        if (results.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No test results to export.", "Information", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("api_auth_test_results.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(target)) {
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                fw.write(gson.toJson(results));
                JOptionPane.showMessageDialog(this, "Exported " + results.size() + " results to " + target.getName(), "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error exporting JSON: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String escapeCsv(String s) {
        if (s == null) return "";
        return s.replace("\"", "\"\"");
    }

    // --- Helpers ---

    private ImportedCollection_littlespidy findCollectionById(String id) {
        if (importTabRef == null || id == null) return null;
        for (ImportedCollection_littlespidy c : importTabRef.getAllCollections()) {
            if (id.equals(c.getId())) return c;
        }
        return null;
    }

    private DiscoveredEndpoint_littlespidy findEndpoint(ImportedCollection_littlespidy col, String method, String path) {
        if (col == null || path == null) return null;
        for (DiscoveredEndpoint_littlespidy ep : col.getEndpoints()) {
            if (ep.getMethod().equalsIgnoreCase(method) && ep.getPath().equalsIgnoreCase(path)) {
                return ep;
            }
        }
        return null;
    }

    private AuthProfile_littlespidy findProfileById(String id) {
        if (id == null || "unauthenticated".equalsIgnoreCase(id)) return null;
        for (AuthProfile_littlespidy p : profiles) {
            if (id.equals(p.getId())) return p;
        }
        return null;
    }

    // --- State Getters and Setters for Persistence ---

    public List<AuthProfile_littlespidy> getAllProfiles() {
        if (configTab != null) {
            return configTab.getAllProfiles();
        }
        return profiles;
    }

    public Set<String> getActiveProfileIds() {
        if (configTab != null) {
            return configTab.getActiveProfileIds();
        }
        return activeProfileIds;
    }

    public List<AuthProfile_littlespidy> getActiveProfiles() {
        if (configTab != null) {
            return configTab.getActiveProfiles();
        }
        List<AuthProfile_littlespidy> active = new ArrayList<>();
        for (AuthProfile_littlespidy p : profiles) {
            if (activeProfileIds.contains(p.getId())) {
                active.add(p);
            }
        }
        return active;
    }

    public void refreshCollectionsCombo() {
        if (configTab != null) {
            configTab.refreshCollectionsCombo();
        }
    }

    public void setProfiles(List<AuthProfile_littlespidy> list) {
        if (configTab != null) {
            configTab.setProfiles(list);
        } else {
            profiles.clear();
            activeProfileIds.clear();
            if (list != null) {
                profiles.addAll(list);
                for (AuthProfile_littlespidy p : profiles) {
                    activeProfileIds.add(p.getId());
                }
            }
        }
        if (importTabRef != null) {
            importTabRef.updateAvailableProfiles(getAllProfiles());
        }
        rebuildModel();
    }

    public List<AuthTestResult_littlespidy> getAllResults() {
        return results;
    }

    public List<EndpointResultRow_littlespidy> getEndpointRows() {
        return Collections.unmodifiableList(endpointRows);
    }

    public List<AuthTestRun_littlespidy> getSavedRuns() {
        return Collections.unmodifiableList(new ArrayList<>(savedRuns));
    }

    public String getSelectedRunnerId() {
        return currentRun != null ? currentRun.getId() : null;
    }

    public int getRunnerCounter() {
        if (configTab != null) {
            return configTab.getRunnerCounter();
        }
        return runnerCounter;
    }

    public void clearAllRunners() {
        savedRuns.clear();
        currentRun = null;
        runnerCounter = 1;
        if (configTab != null) {
            configTab.setRunnerCounter(1);
        }
        loadRun(null);
        updateRunnerCombo();
    }

    public void setSavedRuns(List<AuthTestRun_littlespidy> runs, String selectedRunnerId, int counter) {
        savedRuns.clear();
        if (runs != null && !runs.isEmpty()) {
            for (AuthTestRun_littlespidy r : runs) {
                List<EndpointResultRow_littlespidy> epRows = r.getEndpointRows();
                List<ProfileColumnDef_littlespidy> dispProfiles = r.getDisplayedProfiles();
                if (epRows.isEmpty() && !r.getResults().isEmpty()) {
                    epRows = buildEndpointRows(r.getResults());
                }
                if (dispProfiles.isEmpty()) {
                    dispProfiles = buildDisplayedProfiles(r.getResults(), getAllProfiles(), getActiveProfileIds());
                }
                AuthTestRun_littlespidy fullRun = new AuthTestRun_littlespidy(
                        r.getId(), r.getName(), r.getTimestamp(), r.getResults(), epRows, dispProfiles);
                savedRuns.add(fullRun);
            }
        }

        if (counter > 0) {
            this.runnerCounter = counter;
        } else {
            this.runnerCounter = Math.max(1, savedRuns.size() + 1);
        }
        if (configTab != null) {
            configTab.setRunnerCounter(this.runnerCounter);
        }

        AuthTestRun_littlespidy toSelect = null;
        if (selectedRunnerId != null && !selectedRunnerId.isBlank()) {
            for (AuthTestRun_littlespidy r : savedRuns) {
                if (selectedRunnerId.equals(r.getId())) {
                    toSelect = r;
                    break;
                }
            }
        }
        if (toSelect == null && !savedRuns.isEmpty()) {
            toSelect = savedRuns.get(savedRuns.size() - 1);
        }

        updateRunnerCombo();

        if (toSelect != null) {
            int selIdx = savedRuns.indexOf(toSelect);
            if (selIdx >= 0 && runnerCombo != null) {
                updatingRunnerCombo = true;
                runnerCombo.setSelectedIndex(selIdx);
                updatingRunnerCombo = false;
            }
            loadRun(toSelect);
        } else {
            loadRun(null);
        }
    }

    public void setResults(List<AuthTestResult_littlespidy> list) {
        results.clear();
        if (list != null) {
            results.addAll(list);
            for (AuthTestResult_littlespidy r : list) {
                if (methodFilterDropDown != null && r.getMethod() != null) {
                    methodFilterDropDown.registerMethod(r.getMethod());
                }
            }
        }
        rebuildModel();
        if (savedRuns.isEmpty() && !results.isEmpty()) {
            AuthTestRun_littlespidy run = new AuthTestRun_littlespidy("Runner 1", results, endpointRows, displayedProfiles);
            savedRuns.add(run);
            currentRun = run;
            updateRunnerCombo();
        }
        if (statusFilterDropDown != null) {
            statusFilterDropDown.updateOptions(results);
        }
        applyAllFilters();
    }

    public MethodFilterDropDown_littlespidy getMethodFilterDropDown() {
        return methodFilterDropDown;
    }

    // --- Table Models & Renderers ---

    private class ProfileTableModel extends AbstractTableModel {
        private final String[] columns = {"Test", "Profile Name", "Credentials / Details"};

        @Override public int getRowCount() { return profiles.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Class<?> getColumnClass(int col) { return col == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int row, int col) { return col == 0; }

        @Override
        public void setValueAt(Object aValue, int row, int col) {
            if (col == 0 && aValue instanceof Boolean) {
                AuthProfile_littlespidy p = profiles.get(row);
                if ((Boolean) aValue) {
                    activeProfileIds.add(p.getId());
                } else {
                    activeProfileIds.remove(p.getId());
                }
                fireTableCellUpdated(row, col);
                rebuildModel();
                notifyStateChanged();
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            AuthProfile_littlespidy p = profiles.get(row);
            switch (col) {
                case 0: return activeProfileIds.contains(p.getId());
                case 1: return p.getName();
                case 2: return p.getMaskedSummary();
                default: return "";
            }
        }
    }

    public static class EndpointSelectionItem {
        public final ImportedCollection_littlespidy collection;
        public final DiscoveredEndpoint_littlespidy endpoint;
        public boolean selected;

        public EndpointSelectionItem(ImportedCollection_littlespidy collection, DiscoveredEndpoint_littlespidy endpoint, boolean selected) {
            this.collection = collection;
            this.endpoint = endpoint;
            this.selected = selected;
        }
    }

    private static class EndpointSelectionTableModel extends AbstractTableModel {
        private final String[] columns = {"Test", "Method", "Path", "Summary"};
        private List<EndpointSelectionItem> items = new ArrayList<>();

        public void setItems(List<EndpointSelectionItem> list) {
            this.items = list != null ? list : new ArrayList<>();
            fireTableDataChanged();
        }

        public List<EndpointSelectionItem> getItems() {
            return items;
        }

        public List<EndpointSelectionItem> getSelectedItems() {
            List<EndpointSelectionItem> res = new ArrayList<>();
            for (EndpointSelectionItem it : items) {
                if (it.selected) res.add(it);
            }
            return res;
        }

        public void selectAll(boolean sel) {
            for (EndpointSelectionItem it : items) {
                it.selected = sel;
            }
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return items.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Class<?> getColumnClass(int col) { return col == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int row, int col) { return col == 0; }

        @Override
        public void setValueAt(Object aValue, int row, int col) {
            if (col == 0 && aValue instanceof Boolean) {
                items.get(row).selected = (Boolean) aValue;
                fireTableCellUpdated(row, col);
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            EndpointSelectionItem it = items.get(row);
            switch (col) {
                case 0: return it.selected;
                case 1: return it.endpoint.getMethod();
                case 2: return it.endpoint.getPath();
                case 3: return it.endpoint.getSummary();
                default: return "";
            }
        }
    }

    private void rebuildModel() {
        rebuildDisplayedProfiles();
        rebuildEndpointRows();
        resultsTableModel.fireTableStructureChanged();
    }

    private void rebuildDisplayedProfiles() {
        displayedProfiles.clear();
        displayedProfiles.addAll(buildDisplayedProfiles(results, getAllProfiles(), getActiveProfileIds()));
    }

    private void rebuildEndpointRows() {
        endpointRows.clear();
        endpointRows.addAll(buildEndpointRows(results));
    }

    public static List<ProfileColumnDef_littlespidy> buildDisplayedProfiles(
            List<AuthTestResult_littlespidy> runResults,
            List<AuthProfile_littlespidy> currentProfiles,
            Set<String> activeIds) {
        List<ProfileColumnDef_littlespidy> list = new ArrayList<>();
        Set<String> addedIds = new HashSet<>();

        // 1. Defined profiles strictly in their configured order
        if (currentProfiles != null) {
            for (AuthProfile_littlespidy p : currentProfiles) {
                boolean hasRes = false;
                if (runResults != null) {
                    for (AuthTestResult_littlespidy r : runResults) {
                        if (p.getId().equals(resolveProfileKey(r))) {
                            hasRes = true;
                            break;
                        }
                    }
                }
                if ((activeIds != null && activeIds.contains(p.getId())) || hasRes) {
                    list.add(new ProfileColumnDef_littlespidy(p.getId(), p.getName()));
                    addedIds.add(p.getId());
                }
            }
        }

        // 2. Extra profiles present in results (excluding unauthenticated)
        if (runResults != null) {
            for (AuthTestResult_littlespidy r : runResults) {
                String pid = resolveProfileKey(r);
                if (!"unauthenticated".equalsIgnoreCase(pid) && !addedIds.contains(pid)) {
                    String displayName = (r.getProfileName() != null && !r.getProfileName().isBlank())
                            ? r.getProfileName() : pid;
                    list.add(new ProfileColumnDef_littlespidy(pid, displayName));
                    addedIds.add(pid);
                }
            }

            // 3. Unauthenticated column strictly placed after profiles if present in results
            boolean hasUnauthResults = false;
            for (AuthTestResult_littlespidy r : runResults) {
                if ("unauthenticated".equalsIgnoreCase(resolveProfileKey(r))) {
                    hasUnauthResults = true;
                    break;
                }
            }
            if (hasUnauthResults) {
                list.add(new ProfileColumnDef_littlespidy("unauthenticated", "Unauth"));
            }
        }
        return list;
    }

    public static List<EndpointResultRow_littlespidy> buildEndpointRows(List<AuthTestResult_littlespidy> runResults) {
        List<EndpointResultRow_littlespidy> list = new ArrayList<>();
        if (runResults == null) return list;
        Map<String, EndpointResultRow_littlespidy> rowMap = new LinkedHashMap<>();

        for (AuthTestResult_littlespidy r : runResults) {
            String key = (r.getCollectionId() != null ? r.getCollectionId() : "") + "::"
                    + (r.getMethod() != null ? r.getMethod().toUpperCase() : "") + "::"
                    + (r.getPath() != null ? r.getPath() : "");

            EndpointResultRow_littlespidy row = rowMap.computeIfAbsent(key, k ->
                    new EndpointResultRow_littlespidy(r.getCollectionId(), r.getCollectionName(), r.getMethod(), r.getPath())
            );
            row.getProfileResults().put(resolveProfileKey(r), r);
            if (r.getClassification() != null && !r.getClassification().isBlank()) {
                row.setClassification(r.getClassification());
            }
        }

        list.addAll(rowMap.values());
        return list;
    }

    public static String resolveProfileKey(AuthTestResult_littlespidy r) {
        if (r == null) return "";
        if (r.getProfileId() != null && !r.getProfileId().isBlank()) {
            return r.getProfileId();
        }
        if (r.getProfileName() != null && r.getProfileName().toLowerCase().contains("unauth")) {
            return "unauthenticated";
        }
        return r.getProfileName() != null ? r.getProfileName() : "unknown";
    }

    private boolean hasResultsForProfile(String profileId) {
        if (profileId == null) return false;
        for (AuthTestResult_littlespidy r : results) {
            if (profileId.equals(resolveProfileKey(r))) {
                return true;
            }
        }
        return false;
    }

    public static class ProfileColumnDef_littlespidy {
        private final String id;
        private final String displayName;

        public ProfileColumnDef_littlespidy(String id, String displayName) {
            this.id = id;
            this.displayName = displayName;
        }

        public String getId() { return id; }
        public String getDisplayName() { return displayName; }
    }

    public static class EndpointResultRow_littlespidy {
        private final String collectionId;
        private final String collectionName;
        private final String method;
        private final String path;
        private final Map<String, AuthTestResult_littlespidy> profileResults = new LinkedHashMap<>();
        private String classification;

        public EndpointResultRow_littlespidy(String collectionId, String collectionName, String method, String path) {
            this.collectionId = collectionId;
            this.collectionName = collectionName;
            this.method = method;
            this.path = path;
        }

        public String getCollectionId() { return collectionId; }
        public String getCollectionName() { return collectionName; }
        public String getMethod() { return method; }
        public String getPath() { return path; }
        public Map<String, AuthTestResult_littlespidy> getProfileResults() { return profileResults; }
        public String getClassification() { return classification; }
        public void setClassification(String classification) { this.classification = classification; }
        public String getKey() {
            return (collectionId != null ? collectionId : "") + "::"
                    + (method != null ? method.toUpperCase() : "") + "::"
                    + (path != null ? path : "");
        }
    }

    public static String computeComparativeOutcome(String targetProfileId, EndpointResultRow_littlespidy epRow) {
        if (targetProfileId == null || epRow == null) {
            return "N/A";
        }
        AuthTestResult_littlespidy targetResult = epRow.getProfileResults().get(targetProfileId);
        if (targetResult == null) {
            return "N/A";
        }
        int targetCode = targetResult.getAuthStatusCode();
        if (targetCode == 0) {
            return "N/A";
        }

        byte[] targetBody = targetResult.getAuthResponseBytes();
        int targetLen = targetResult.getAuthResponseLength();

        if (targetCode == 401 || targetCode == 403) {
            if (epRow.getProfileResults().size() > 1) {
                return "DIFFERENT";
            }
            return "N/A";
        }

        String bestOutcome = null;

        for (Map.Entry<String, AuthTestResult_littlespidy> entry : epRow.getProfileResults().entrySet()) {
            String peerId = entry.getKey();
            if (peerId.equals(targetProfileId)) {
                continue;
            }

            AuthTestResult_littlespidy peerResult = entry.getValue();
            if (peerResult == null) continue;
            int peerCode = peerResult.getAuthStatusCode();
            if (peerCode == 0) continue;

            if (peerCode == 401 || peerCode == 403) {
                if (bestOutcome == null) {
                    bestOutcome = "DIFFERENT";
                }
                continue;
            }

            if (targetCode == peerCode) {
                byte[] peerBody = peerResult.getAuthResponseBytes();
                int peerLen = peerResult.getAuthResponseLength();

                boolean exactMatch = false;
                if (targetBody != null && peerBody != null && targetBody.length > 0) {
                    exactMatch = Arrays.equals(targetBody, peerBody);
                } else if (targetLen == peerLen && targetLen > 0) {
                    exactMatch = true;
                }

                if (exactMatch) {
                    return "SAME"; // Highest severity IDOR Bypass
                }

                int baseLength = Math.max(targetLen, peerLen);
                int range = baseLength > 0 ? (baseLength / 20) : 0; // +-5% matching ng-auth-analyzer
                int diff = Math.abs(targetLen - peerLen);
                if (diff <= range) {
                    bestOutcome = "SIMILAR";
                } else {
                    if (bestOutcome == null) {
                        bestOutcome = "DIFFERENT";
                    }
                }
            } else {
                if (bestOutcome == null) {
                    bestOutcome = "DIFFERENT";
                }
            }
        }

        return bestOutcome != null ? bestOutcome : "N/A";
    }

    private class ResultsTableModel extends AbstractTableModel {
        private final String[] baseColumns = {"Collection", "Method", "Path"};

        @Override public int getRowCount() { return endpointRows.size(); }
        @Override public int getColumnCount() { return baseColumns.length + displayedProfiles.size(); }

        @Override
        public String getColumnName(int col) {
            if (col < baseColumns.length) {
                return baseColumns[col];
            }
            int profileIdx = col - baseColumns.length;
            if (profileIdx < displayedProfiles.size()) {
                return displayedProfiles.get(profileIdx).getDisplayName();
            }
            return "";
        }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= endpointRows.size()) {
                return null;
            }
            EndpointResultRow_littlespidy epRow = endpointRows.get(row);
            if (col == 0) return epRow.getCollectionName();
            if (col == 1) return epRow.getMethod();
            if (col == 2) return epRow.getPath();

            int profileIdx = col - baseColumns.length;
            if (profileIdx < displayedProfiles.size()) {
                ProfileColumnDef_littlespidy def = displayedProfiles.get(profileIdx);
                AuthTestResult_littlespidy res = epRow.getProfileResults().get(def.getId());
                if (res != null && res.getAuthStatusCode() > 0) {
                    return String.valueOf(res.getAuthStatusCode());
                }
                return "-";
            }
            return "-";
        }
    }

    private static class CollectionComboItem {
        public final ImportedCollection_littlespidy collection;
        public final String label;

        public CollectionComboItem(ImportedCollection_littlespidy collection, String label) {
            this.collection = collection;
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /**
     * Side-by-side profile column viewer following the architecture and design patterns
     * from ng-auth-analyzer_littlespidy (SessionColumnView).
     */
    public static class ProfileColumnView {
        final JPanel panel = new JPanel(new BorderLayout());
        final CardLayout cardLayout = new CardLayout();
        final JPanel cardPanel = new JPanel(cardLayout);

        public ProfileColumnView(String title, String info, Color headerBg, Component reqComp, Component respComp) {
            JPanel header = new JPanel(new BorderLayout(5, 2));
            header.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                    BorderFactory.createEmptyBorder(4, 6, 4, 6)));
            if (headerBg != null) {
                header.setBackground(headerBg);
            }
            JLabel titleLabel = new JLabel(title);
            titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
            JLabel infoLabel = new JLabel(info);
            header.add(titleLabel, BorderLayout.WEST);
            header.add(infoLabel, BorderLayout.EAST);

            cardPanel.add(reqComp != null ? reqComp : new JLabel("No Request Available", JLabel.CENTER), "REQ");
            cardPanel.add(respComp != null ? respComp : new JLabel("No Response Available", JLabel.CENTER), "RESP");

            panel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
            panel.add(header, BorderLayout.NORTH);
            panel.add(cardPanel, BorderLayout.CENTER);
        }

        public void setViewMode(int mode) {
            if (mode == 0) {
                cardLayout.show(cardPanel, "REQ");
            } else {
                cardLayout.show(cardPanel, "RESP");
            }
        }
    }

    /**
     * Named test run entity representing completed or active auth test execution.
     */
    public static class AuthTestRun_littlespidy {
        private final String id;
        private final String name;
        private final long timestamp;
        private final List<AuthTestResult_littlespidy> results = new ArrayList<>();
        private final List<EndpointResultRow_littlespidy> endpointRows = new ArrayList<>();
        private final List<ProfileColumnDef_littlespidy> displayedProfiles = new ArrayList<>();

        public AuthTestRun_littlespidy(String name,
                                       List<AuthTestResult_littlespidy> results,
                                       List<EndpointResultRow_littlespidy> endpointRows,
                                       List<ProfileColumnDef_littlespidy> displayedProfiles) {
            this(UUID.randomUUID().toString(), name, System.currentTimeMillis(), results, endpointRows, displayedProfiles);
        }

        public AuthTestRun_littlespidy(String id,
                                       String name,
                                       long timestamp,
                                       List<AuthTestResult_littlespidy> results,
                                       List<EndpointResultRow_littlespidy> endpointRows,
                                       List<ProfileColumnDef_littlespidy> displayedProfiles) {
            this.id = (id != null && !id.isBlank()) ? id : UUID.randomUUID().toString();
            this.name = name != null ? name : "Run";
            this.timestamp = timestamp > 0 ? timestamp : System.currentTimeMillis();
            if (results != null) this.results.addAll(results);
            if (endpointRows != null) this.endpointRows.addAll(endpointRows);
            if (displayedProfiles != null) this.displayedProfiles.addAll(displayedProfiles);
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public long getTimestamp() { return timestamp; }
        public List<AuthTestResult_littlespidy> getResults() { return results; }
        public List<EndpointResultRow_littlespidy> getEndpointRows() { return endpointRows; }
        public List<ProfileColumnDef_littlespidy> getDisplayedProfiles() { return displayedProfiles; }

        @Override
        public String toString() {
            return name + " (" + results.size() + " results)";
        }
    }
}
