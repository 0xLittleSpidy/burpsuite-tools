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
    private final List<AuthProfile_littlespidy> profiles = new ArrayList<>();
    private final Set<String> activeProfileIds = new HashSet<>();
    private final List<AuthTestResult_littlespidy> results = new ArrayList<>();

    private APIImportTab_littlespidy importTabRef;
    private final List<Runnable> stateChangedListeners = new ArrayList<>();

    // Profiles UI
    private ProfileTableModel profileTableModel;
    private JTable profileTable;

    // Endpoints Selection UI
    private JComboBox<CollectionComboItem> collectionSelectorCombo;
    private EndpointSelectionTableModel endpointSelectionModel;
    private JTable endpointSelectionTable;

    // Execution Controls UI
    private JButton runAllBtn;
    private JButton runSelectedBtn;
    private JButton cancelBtn;
    private JSpinner threadSpinner;
    private JSpinner delaySpinner;
    private JProgressBar progressBar;
    private JLabel progressStatusLabel;

    // Results UI
    private ResultsTableModel resultsTableModel;
    private JTable resultsTable;
    private TableRowSorter<ResultsTableModel> resultsSorter;
    private JComboBox<String> outcomeFilterCombo;
    private ProfileStatusFilterDropDown_littlespidy statusFilterDropDown;
    private JButton deleteRunnerBtn;

    // Per-profile columns and endpoint-based result rows matching ng-auth-analyzer_littlespidy
    private final List<EndpointResultRow_littlespidy> endpointRows = new ArrayList<>();
    private final List<ProfileColumnDef_littlespidy> displayedProfiles = new ArrayList<>();
    private final OutcomeCellRenderer outcomeCellRenderer = new OutcomeCellRenderer();

    // Runner History Management
    private final List<AuthTestRun_littlespidy> savedRuns = new ArrayList<>();
    private AuthTestRun_littlespidy currentRun;
    private int runnerCounter = 1;
    private String currentRunName = "Runner 1";
    private JTextField runnerNameField;
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

    public void setImportTabRef(APIImportTab_littlespidy importTabRef) {
        this.importTabRef = importTabRef;
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
            importTabRef.updateAvailableProfiles(profiles);
        }
    }

    private void initComponents() {
        // Main Split Pane: Left (Profiles & Endpoints Configuration), Right (Test Results & Inspection)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.40);
        mainSplit.setContinuousLayout(true);

        // --- LEFT PANE: Profiles + Endpoints Selector ---
        JPanel leftPane = new JPanel(new BorderLayout(6, 6));

        // 1. Top Left: Profiles Management
        JPanel profilesPanel = new JPanel(new BorderLayout(4, 4));
        profilesPanel.setBorder(new TitledBorder("Authentication Profiles"));

        profileTableModel = new ProfileTableModel();
        profileTable = new JTable(profileTableModel);
        profileTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        profileTable.getColumnModel().getColumn(0).setMaxWidth(45);
        profileTable.getColumnModel().getColumn(0).setPreferredWidth(45);
        profileTable.addKeyListener(new java.awt.event.KeyAdapter() {
            @Override
            public void keyPressed(java.awt.event.KeyEvent e) {
                if (e.getKeyCode() == java.awt.event.KeyEvent.VK_SPACE) {
                    int[] rows = profileTable.getSelectedRows();
                    if (rows.length > 0) {
                        int firstModelRow = profileTable.convertRowIndexToModel(rows[0]);
                        boolean newState = !activeProfileIds.contains(profiles.get(firstModelRow).getId());
                        for (int r : rows) {
                            int modelRow = profileTable.convertRowIndexToModel(r);
                            if (modelRow >= 0 && modelRow < profiles.size()) {
                                AuthProfile_littlespidy p = profiles.get(modelRow);
                                if (newState) {
                                    activeProfileIds.add(p.getId());
                                } else {
                                    activeProfileIds.remove(p.getId());
                                }
                            }
                        }
                        profileTableModel.fireTableDataChanged();
                        rebuildModel();
                        notifyStateChanged();
                        e.consume();
                    }
                }
            }
        });
        JScrollPane profileScroll = new JScrollPane(profileTable);
        profileScroll.setPreferredSize(new Dimension(380, 140));
        profilesPanel.add(profileScroll, BorderLayout.CENTER);

        JPanel profileActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton addProfBtn = new JButton("New Profile");
        addProfBtn.addActionListener(e -> onNewProfile());
        JButton editProfBtn = new JButton("Edit Profile");
        editProfBtn.addActionListener(e -> onEditProfile());
        JButton dupProfBtn = new JButton("Duplicate");
        dupProfBtn.addActionListener(e -> onDuplicateProfile());
        JButton delProfBtn = new JButton("Delete");
        delProfBtn.addActionListener(e -> onDeleteProfile());

        profileActions.add(addProfBtn);
        profileActions.add(editProfBtn);
        profileActions.add(dupProfBtn);
        profileActions.add(delProfBtn);
        profilesPanel.add(profileActions, BorderLayout.SOUTH);

        // 2. Center Left: Collection & Endpoints Selection Panel
        JPanel endpointsPanel = new JPanel(new BorderLayout(4, 4));
        endpointsPanel.setBorder(new TitledBorder("Endpoints to Test"));

        JPanel colSelectBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        colSelectBar.add(new JLabel("Collection:"));
        collectionSelectorCombo = new JComboBox<>();
        collectionSelectorCombo.setPreferredSize(new Dimension(220, 24));
        collectionSelectorCombo.addActionListener(e -> onCollectionSelectionChanged());
        colSelectBar.add(collectionSelectorCombo);

        JButton reloadColsBtn = new JButton("Refresh");
        reloadColsBtn.setToolTipText("Reload collections from API Import tab");
        reloadColsBtn.addActionListener(e -> refreshCollectionsCombo());
        colSelectBar.add(reloadColsBtn);
        endpointsPanel.add(colSelectBar, BorderLayout.NORTH);

        endpointSelectionModel = new EndpointSelectionTableModel();
        endpointSelectionTable = new JTable(endpointSelectionModel);
        endpointSelectionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointSelectionTable.getColumnModel().getColumn(0).setMaxWidth(40);
        endpointSelectionTable.getColumnModel().getColumn(1).setMaxWidth(70);
        endpointSelectionTable.addKeyListener(new java.awt.event.KeyAdapter() {
            @Override
            public void keyPressed(java.awt.event.KeyEvent e) {
                if (e.getKeyCode() == java.awt.event.KeyEvent.VK_SPACE) {
                    int[] rows = endpointSelectionTable.getSelectedRows();
                    if (rows.length > 0) {
                        int firstModelRow = endpointSelectionTable.convertRowIndexToModel(rows[0]);
                        List<EndpointSelectionItem> items = endpointSelectionModel.getItems();
                        if (firstModelRow >= 0 && firstModelRow < items.size()) {
                            boolean newState = !items.get(firstModelRow).selected;
                            for (int r : rows) {
                                int modelRow = endpointSelectionTable.convertRowIndexToModel(r);
                                if (modelRow >= 0 && modelRow < items.size()) {
                                    items.get(modelRow).selected = newState;
                                }
                            }
                            endpointSelectionModel.fireTableDataChanged();
                            e.consume();
                        }
                    }
                }
            }
        });
        JScrollPane epScroll = new JScrollPane(endpointSelectionTable);
        endpointsPanel.add(epScroll, BorderLayout.CENTER);

        // Combine Profiles and Endpoints in Left Split
        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, profilesPanel, endpointsPanel);
        leftSplit.setResizeWeight(0.32);
        leftSplit.setContinuousLayout(true);
        leftPane.add(leftSplit, BorderLayout.CENTER);

        // 3. Bottom Left: Execution Controls Bar
        JPanel execControlsPanel = new JPanel(new GridBagLayout());
        execControlsPanel.setBorder(new TitledBorder("Execution Controls"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        execControlsPanel.add(new JLabel("Threads:"), gbc);
        threadSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 20, 1));
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.5;
        execControlsPanel.add(threadSpinner, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        execControlsPanel.add(new JLabel("Delay (ms):"), gbc);
        delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 5000, 25));
        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0.5;
        execControlsPanel.add(delaySpinner, gbc);

        JPanel runBtnBox = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 2));
        runBtnBox.add(new JLabel("Runner:"));
        runnerNameField = new JTextField("Runner 1", 9);
        runnerNameField.setToolTipText("Name for this test run / runner");
        runBtnBox.add(runnerNameField);

        runAllBtn = new JButton("Attack");
        runAllBtn.setFont(runAllBtn.getFont().deriveFont(Font.BOLD));
        runAllBtn.addActionListener(e -> onRunAllInCollection());
        runSelectedBtn = new JButton("Test Selected");
        runSelectedBtn.addActionListener(e -> onRunSelectedEndpoints());
        cancelBtn = new JButton("Cancel");
        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancelRun());

        runBtnBox.add(runAllBtn);
        runBtnBox.add(runSelectedBtn);
        runBtnBox.add(cancelBtn);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 4;
        execControlsPanel.add(runBtnBox, gbc);

        // Progress status
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        progressStatusLabel = new JLabel("Ready");
        progressStatusLabel.setFont(progressStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 4;
        execControlsPanel.add(progressStatusLabel, gbc);
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4;
        execControlsPanel.add(progressBar, gbc);

        leftPane.add(execControlsPanel, BorderLayout.SOUTH);
        mainSplit.setLeftComponent(leftPane);

        // --- RIGHT PANE: Results Table & Side-by-Side HTTP Message Inspector ---
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setResizeWeight(0.50);
        rightSplit.setContinuousLayout(true);

        // Top Right: Results Table
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

        leftFilter.add(new JLabel("Outcome:"));
        outcomeFilterCombo = new JComboBox<>(new String[]{
                "All Outcomes",
                "Status SAME (Bypassed)",
                "Status SIMILAR (Potential Bypass)",
                "Status DIFFERENT (Enforced)",
                "Status N/A"
        });
        outcomeFilterCombo.addActionListener(e -> applyAllFilters());
        leftFilter.add(outcomeFilterCombo);

        statusFilterDropDown = new ProfileStatusFilterDropDown_littlespidy();
        statusFilterDropDown.addFilterChangeListener(this::applyAllFilters);
        leftFilter.add(statusFilterDropDown);

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
            public TableCellRenderer getCellRenderer(int row, int column) {
                // Profile outcome columns are even offsets starting from index 3
                if (column >= 3) {
                    int rel = column - 3;
                    if ((rel % 2) == 0) {
                        return outcomeCellRenderer;
                    }
                }
                return super.getCellRenderer(row, column);
            }
        };
        resultsSorter = new TableRowSorter<>(resultsTableModel);
        resultsTable.setRowSorter(resultsSorter);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onResultRowSelected();
            }
        });

        JScrollPane resScroll = new JScrollPane(resultsTable);
        resultsPanel.add(resScroll, BorderLayout.CENTER);
        rightSplit.setTopComponent(resultsPanel);

        // Bottom Right: Multi-Column Compare Viewer
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

        rightSplit.setBottomComponent(inspectorPanel);

        mainSplit.setRightComponent(rightSplit);
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

    // --- Profile Management Actions ---

    private void onNewProfile() {
        Window win = SwingUtilities.getWindowAncestor(this);
        AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(win, "Create Authentication Profile", null, p -> {
            profiles.add(p);
            activeProfileIds.add(p.getId());
            profileTableModel.fireTableDataChanged();
            rebuildModel();
            notifyStateChanged();
        });
        dialog.setVisible(true);
    }

    private void onEditProfile() {
        int row = profileTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a profile to edit.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = profileTable.convertRowIndexToModel(row);
        AuthProfile_littlespidy p = profiles.get(modelRow);
        Window win = SwingUtilities.getWindowAncestor(this);
        AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(win, "Edit Authentication Profile", p, updated -> {
            profileTableModel.fireTableRowsUpdated(modelRow, modelRow);
            rebuildModel();
            notifyStateChanged();
        });
        dialog.setVisible(true);
    }

    private void onDuplicateProfile() {
        int row = profileTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a profile to duplicate.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        AuthProfile_littlespidy copy = profiles.get(row).copy();
        profiles.add(copy);
        activeProfileIds.add(copy.getId());
        profileTableModel.fireTableDataChanged();
        rebuildModel();
        notifyStateChanged();
    }

    private void onDeleteProfile() {
        int row = profileTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a profile to delete.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        AuthProfile_littlespidy p = profiles.get(row);
        int confirm = JOptionPane.showConfirmDialog(this,
                "Delete authentication profile \"" + p.getName() + "\"?",
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            activeProfileIds.remove(p.getId());
            profiles.remove(row);
            profileTableModel.fireTableDataChanged();
            rebuildModel();
            notifyStateChanged();
        }
    }

    private void selectAllProfiles(boolean select) {
        if (select) {
            for (AuthProfile_littlespidy p : profiles) {
                activeProfileIds.add(p.getId());
            }
        } else {
            activeProfileIds.clear();
        }
        profileTableModel.fireTableDataChanged();
        rebuildModel();
    }

    public List<AuthProfile_littlespidy> getActiveProfiles() {
        List<AuthProfile_littlespidy> active = new ArrayList<>();
        for (AuthProfile_littlespidy p : profiles) {
            if (activeProfileIds.contains(p.getId())) {
                active.add(p);
            }
        }
        return active;
    }

    // --- Collection & Endpoints Selection Actions ---

    public void refreshCollectionsCombo() {
        collectionSelectorCombo.removeAllItems();
        if (importTabRef != null) {
            List<ImportedCollection_littlespidy> allCols = importTabRef.getAllCollections();
            collectionSelectorCombo.addItem(new CollectionComboItem(null, "[All Imported Collections]"));
            for (ImportedCollection_littlespidy c : allCols) {
                collectionSelectorCombo.addItem(new CollectionComboItem(c, c.getName() + " (" + c.getEndpointCount() + ")"));
            }
        }
        onCollectionSelectionChanged();
    }

    private void onCollectionSelectionChanged() {
        CollectionComboItem sel = (CollectionComboItem) collectionSelectorCombo.getSelectedItem();
        if (sel == null || sel.collection == null) {
            // All collections
            if (importTabRef != null) {
                List<EndpointSelectionItem> all = new ArrayList<>();
                for (ImportedCollection_littlespidy c : importTabRef.getAllCollections()) {
                    for (DiscoveredEndpoint_littlespidy ep : c.getEndpoints()) {
                        all.add(new EndpointSelectionItem(c, ep, true));
                    }
                }
                endpointSelectionModel.setItems(all);
            } else {
                endpointSelectionModel.setItems(Collections.emptyList());
            }
        } else {
            List<EndpointSelectionItem> items = new ArrayList<>();
            for (DiscoveredEndpoint_littlespidy ep : sel.collection.getEndpoints()) {
                items.add(new EndpointSelectionItem(sel.collection, ep, true));
            }
            endpointSelectionModel.setItems(items);
        }
    }

    // --- Execution Actions ---

    private void onRunAllInCollection() {
        endpointSelectionModel.selectAll(true);
        executeTestsForItems(endpointSelectionModel.getItems());
    }

    private void onRunSelectedEndpoints() {
        List<EndpointSelectionItem> selected = endpointSelectionModel.getSelectedItems();
        if (selected.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No endpoints selected. Check the box next to endpoints you want to test.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        executeTestsForItems(selected);
    }

    private void executeTestsForItems(List<EndpointSelectionItem> items) {
        if (items.isEmpty()) return;

        List<AuthProfile_littlespidy> activeProfiles = getActiveProfiles();

        if (activeProfiles.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please select at least one authentication profile.",
                    "Configuration Required",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<EndpointTestTarget> targets = new ArrayList<>();
        for (EndpointSelectionItem it : items) {
            for (AuthProfile_littlespidy p : activeProfiles) {
                targets.add(new EndpointTestTarget(it.collection, it.endpoint, p));
            }
        }

        int threads = (Integer) threadSpinner.getValue();
        int delay = (Integer) delaySpinner.getValue();

        currentRunName = (runnerNameField != null && !runnerNameField.getText().trim().isEmpty())
                ? runnerNameField.getText().trim()
                : ("Runner " + runnerCounter);
        results.clear();
        endpointRows.clear();

        rebuildDisplayedProfiles();
        resultsTableModel.fireTableStructureChanged();

        setExecutionUIState(true);
        testEngine.startTesting(targets, threads, delay, false, this);
    }

    private void onCancelRun() {
        testEngine.stopTesting();
        progressStatusLabel.setText("Cancelling test run...");
        cancelBtn.setEnabled(false);
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

        int threads = (Integer) threadSpinner.getValue();
        int delay = (Integer) delaySpinner.getValue();

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
                displayedProfiles.addAll(buildDisplayedProfiles(results, profiles, activeProfileIds));
            } else {
                displayedProfiles.addAll(run.getDisplayedProfiles());
            }
        }
        resultsTableModel.fireTableStructureChanged();
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
        runAllBtn.setEnabled(!running);
        runSelectedBtn.setEnabled(!running);
        cancelBtn.setEnabled(running);
        progressBar.setVisible(running);
    }

    // --- Progress Listener Implementation ---

    @Override
    public void onTestStarted(int totalEndpoints) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setMinimum(0);
            progressBar.setMaximum(totalEndpoints);
            progressBar.setValue(0);
            progressStatusLabel.setText("Testing 0 of " + totalEndpoints + " configurations...");
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

            progressBar.setValue(completedCount);
            progressStatusLabel.setText("Completed " + completedCount + " of " + totalCount + " configurations");
            if (statusFilterDropDown != null) {
                statusFilterDropDown.updateOptions(results);
            }
            notifyStateChanged();
        });
    }

    @Override
    public void onTestError(String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            progressStatusLabel.setText("Error: " + errorMessage);
        });
    }

    @Override
    public void onTestFinished(boolean cancelled, int totalCompleted) {
        SwingUtilities.invokeLater(() -> {
            setExecutionUIState(false);
            if (cancelled) {
                progressStatusLabel.setText("Test run cancelled. Total completed: " + totalCompleted);
            } else {
                progressStatusLabel.setText("Test run finished. Total completed: " + totalCompleted);
            }
            rebuildModel();
            AuthTestRun_littlespidy run = new AuthTestRun_littlespidy(currentRunName, results, endpointRows, displayedProfiles);
            savedRuns.add(run);
            currentRun = run;
            updateRunnerCombo();
            if (statusFilterDropDown != null) {
                statusFilterDropDown.updateOptions(results);
            }
            applyAllFilters();
            runnerCounter++;
            if (runnerNameField != null) {
                runnerNameField.setText("Runner " + runnerCounter);
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
            String compOutcome = computeComparativeOutcome(def.getId(), selectedEndpointRow);
            String info = (code > 0 ? code : "-") + " | " + (len >= 0 ? len + " B" : "-") + " | " + compOutcome;

            Color colHeaderBg = null;
            if ("SAME".equalsIgnoreCase(compOutcome)) {
                colHeaderBg = new Color(255, 51, 51, 90);
            } else if ("SIMILAR".equalsIgnoreCase(compOutcome)) {
                colHeaderBg = new Color(255, 153, 0, 90);
            } else if ("DIFFERENT".equalsIgnoreCase(compOutcome)) {
                colHeaderBg = new Color(0, 255, 51, 90);
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
        String sel = outcomeFilterCombo != null ? (String) outcomeFilterCombo.getSelectedItem() : "All Outcomes";
        boolean hasOutcomeFilter = sel != null && !"All Outcomes".equals(sel);

        RowFilter<ResultsTableModel, Integer> filter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ResultsTableModel, ? extends Integer> entry) {
                int rowIdx = entry.getIdentifier();
                if (rowIdx < 0 || rowIdx >= endpointRows.size()) {
                    return false;
                }
                EndpointResultRow_littlespidy epRow = endpointRows.get(rowIdx);

                // 1. Outcome filter
                if (hasOutcomeFilter) {
                    boolean outcomeMatch = false;
                    for (ProfileColumnDef_littlespidy def : displayedProfiles) {
                        String outcome = computeComparativeOutcome(def.getId(), epRow);
                        if (sel.contains("SAME") && "SAME".equalsIgnoreCase(outcome)) { outcomeMatch = true; break; }
                        if (sel.contains("SIMILAR") && "SIMILAR".equalsIgnoreCase(outcome)) { outcomeMatch = true; break; }
                        if (sel.contains("DIFFERENT") && "DIFFERENT".equalsIgnoreCase(outcome)) { outcomeMatch = true; break; }
                        if (sel.contains("N/A") && "N/A".equalsIgnoreCase(outcome)) { outcomeMatch = true; break; }
                    }
                    if (!outcomeMatch) {
                        return false;
                    }
                }

                // 2. Profile - Status Code filter
                if (statusFilterDropDown != null && !statusFilterDropDown.matches(epRow)) {
                    return false;
                }

                return true;
            }
        };
        resultsSorter.setRowFilter(filter);
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
        return profiles;
    }

    public void setProfiles(List<AuthProfile_littlespidy> list) {
        profiles.clear();
        activeProfileIds.clear();
        if (list != null) {
            profiles.addAll(list);
            for (AuthProfile_littlespidy p : profiles) {
                activeProfileIds.add(p.getId());
            }
        }
        profileTableModel.fireTableDataChanged();
        if (importTabRef != null) {
            importTabRef.updateAvailableProfiles(profiles);
        }
        rebuildModel();
    }

    public List<AuthTestResult_littlespidy> getAllResults() {
        return results;
    }

    public List<AuthTestRun_littlespidy> getSavedRuns() {
        return Collections.unmodifiableList(new ArrayList<>(savedRuns));
    }

    public String getSelectedRunnerId() {
        return currentRun != null ? currentRun.getId() : null;
    }

    public int getRunnerCounter() {
        return runnerCounter;
    }

    public void clearAllRunners() {
        savedRuns.clear();
        currentRun = null;
        runnerCounter = 1;
        if (runnerNameField != null) {
            runnerNameField.setText("Runner 1");
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
                    dispProfiles = buildDisplayedProfiles(r.getResults(), profiles, activeProfileIds);
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
        if (runnerNameField != null) {
            runnerNameField.setText("Runner " + this.runnerCounter);
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
        displayedProfiles.addAll(buildDisplayedProfiles(results, profiles, activeProfileIds));
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
        @Override public int getColumnCount() { return baseColumns.length + (displayedProfiles.size() * 2); }

        @Override
        public String getColumnName(int col) {
            if (col < baseColumns.length) {
                return baseColumns[col];
            }
            int rel = col - baseColumns.length;
            int profileIdx = rel / 2;
            boolean isStatusCodeCol = (rel % 2) != 0;
            if (profileIdx < displayedProfiles.size()) {
                String profName = displayedProfiles.get(profileIdx).getDisplayName();
                return isStatusCodeCol ? (profName + " - Status Code") : profName;
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

            int rel = col - baseColumns.length;
            int profileIdx = rel / 2;
            boolean isStatusCodeCol = (rel % 2) != 0;
            if (profileIdx < displayedProfiles.size()) {
                ProfileColumnDef_littlespidy def = displayedProfiles.get(profileIdx);
                if (!isStatusCodeCol) {
                    return computeComparativeOutcome(def.getId(), epRow);
                } else {
                    AuthTestResult_littlespidy res = epRow.getProfileResults().get(def.getId());
                    if (res != null && res.getAuthStatusCode() > 0) {
                        return String.valueOf(res.getAuthStatusCode());
                    }
                    return "-";
                }
            }
            return isStatusCodeCol ? "-" : "N/A";
        }
    }

    private static class OutcomeCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (!isSelected && value != null) {
                String str = value.toString();
                if ("SAME".equalsIgnoreCase(str)) {
                    c.setBackground(new Color(255, 51, 51, 80)); // Red (Bypass / IDOR)
                    c.setForeground(new Color(180, 0, 0));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("SIMILAR".equalsIgnoreCase(str)) {
                    c.setBackground(new Color(255, 153, 0, 80)); // Orange (Potential Bypass)
                    c.setForeground(new Color(204, 102, 0));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("DIFFERENT".equalsIgnoreCase(str)) {
                    c.setBackground(new Color(0, 255, 51, 80)); // Green (Enforced)
                    c.setForeground(new Color(0, 128, 0));
                    c.setFont(c.getFont().deriveFont(Font.PLAIN));
                } else {
                    c.setBackground(table.getBackground());
                    c.setForeground(table.getForeground());
                    c.setFont(c.getFont().deriveFont(Font.PLAIN));
                }
            } else if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
            }
            return c;
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
