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
    private JCheckBox unauthCompareToggle;
    private ResultsTableModel resultsTableModel;
    private JTable resultsTable;
    private TableRowSorter<ResultsTableModel> resultsSorter;
    private JComboBox<String> outcomeFilterCombo;

    // HTTP Message Inspector (Compare View following ng-auth-analyzer_littlespidy)
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
        profileTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        profileTable.getColumnModel().getColumn(0).setMaxWidth(45);
        profileTable.getColumnModel().getColumn(0).setPreferredWidth(45);
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
        JButton selectAllProfBtn = new JButton("Select All");
        selectAllProfBtn.addActionListener(e -> selectAllProfiles(true));
        JButton deselectAllProfBtn = new JButton("Deselect All");
        deselectAllProfBtn.addActionListener(e -> selectAllProfiles(false));

        profileActions.add(addProfBtn);
        profileActions.add(editProfBtn);
        profileActions.add(dupProfBtn);
        profileActions.add(delProfBtn);
        profileActions.add(selectAllProfBtn);
        profileActions.add(deselectAllProfBtn);
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
        endpointSelectionTable.getColumnModel().getColumn(0).setMaxWidth(40);
        endpointSelectionTable.getColumnModel().getColumn(1).setMaxWidth(70);
        JScrollPane epScroll = new JScrollPane(endpointSelectionTable);
        endpointsPanel.add(epScroll, BorderLayout.CENTER);

        JPanel epSelectControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> endpointSelectionModel.selectAll(true));
        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> endpointSelectionModel.selectAll(false));
        epSelectControls.add(selectAllBtn);
        epSelectControls.add(deselectAllBtn);
        endpointsPanel.add(epSelectControls, BorderLayout.SOUTH);

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

        JPanel runBtnBox = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 2));
        runAllBtn = new JButton("Run Authentication Tests");
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
        leftFilter.add(new JLabel("Filter Outcome:"));
        outcomeFilterCombo = new JComboBox<>(new String[]{
                "All Outcomes",
                "Unauthenticated Accessible",
                "Authenticated Only",
                "Auth Rejected",
                "Success",
                "Errors"
        });
        outcomeFilterCombo.addActionListener(e -> applyOutcomeFilter());
        leftFilter.add(outcomeFilterCombo);

        // Unauthenticated comparison option prominently positioned above results table
        unauthCompareToggle = new JCheckBox("Run unauthenticated comparison test for each endpoint", true);
        unauthCompareToggle.setFont(unauthCompareToggle.getFont().deriveFont(Font.BOLD));
        unauthCompareToggle.setToolTipText("When enabled, includes unauthenticated test results alongside each profile for comparative analysis");
        leftFilter.add(unauthCompareToggle);

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
        resultsTable = new JTable(resultsTableModel);
        resultsSorter = new TableRowSorter<>(resultsTableModel);
        resultsTable.setRowSorter(resultsSorter);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onResultRowSelected();
            }
        });

        // Custom status/outcome column renderer at column index 6
        resultsTable.getColumnModel().getColumn(6).setCellRenderer(new OutcomeCellRenderer());

        JScrollPane resScroll = new JScrollPane(resultsTable);
        resultsPanel.add(resScroll, BorderLayout.CENTER);
        rightSplit.setTopComponent(resultsPanel);

        // Bottom Right: Multi-Column Compare Viewer (HTTP Message Inspector following ng-auth-analyzer)
        JPanel messageViewHeaderPanel = new JPanel(new BorderLayout());
        JLabel compareTitleLabel = new JLabel("HTTP Message Inspector (Side-by-Side Profile Comparison)");
        compareTitleLabel.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));

        JPanel rightSwitchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        JLabel switchLabel = new JLabel("View:");
        ButtonGroup viewGroup = new ButtonGroup();
        requestToggleButton = new JToggleButton("Request");
        responseToggleButton = new JToggleButton("Response");
        viewGroup.add(requestToggleButton);
        viewGroup.add(responseToggleButton);
        requestToggleButton.setSelected(true);
        requestToggleButton.addActionListener(e -> setInspectorViewMode(0));
        responseToggleButton.addActionListener(e -> setInspectorViewMode(1));

        rightSwitchPanel.add(switchLabel);
        rightSwitchPanel.add(requestToggleButton);
        rightSwitchPanel.add(responseToggleButton);

        messageViewHeaderPanel.add(compareTitleLabel, BorderLayout.WEST);
        messageViewHeaderPanel.add(rightSwitchPanel, BorderLayout.EAST);

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
        AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(win, "Create Authentication Profile", null);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            AuthProfile_littlespidy p = dialog.getProfile();
            profiles.add(p);
            activeProfileIds.add(p.getId());
            profileTableModel.fireTableDataChanged();
            notifyStateChanged();
        }
    }

    private void onEditProfile() {
        int row = profileTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a profile to edit.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        AuthProfile_littlespidy p = profiles.get(row);
        Window win = SwingUtilities.getWindowAncestor(this);
        AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(win, "Edit Authentication Profile", p);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            profileTableModel.fireTableRowsUpdated(row, row);
            notifyStateChanged();
        }
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
        boolean runUnauth = unauthCompareToggle.isSelected();

        if (activeProfiles.isEmpty() && !runUnauth) {
            JOptionPane.showMessageDialog(this,
                    "Please select at least one authentication profile or enable unauthenticated comparison testing.",
                    "Configuration Required",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<EndpointTestTarget> targets = new ArrayList<>();
        for (EndpointSelectionItem it : items) {
            for (AuthProfile_littlespidy p : activeProfiles) {
                targets.add(new EndpointTestTarget(it.collection, it.endpoint, p));
            }
            if (runUnauth) {
                targets.add(new EndpointTestTarget(it.collection, it.endpoint, null));
            }
        }

        int threads = (Integer) threadSpinner.getValue();
        int delay = (Integer) delaySpinner.getValue();

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
        results.clear();
        resultsTableModel.fireTableDataChanged();
        clearInspector();
        notifyStateChanged();
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
            resultsTableModel.fireTableDataChanged();
            progressBar.setValue(completedCount);
            progressStatusLabel.setText("Completed " + completedCount + " of " + totalCount + " configurations");
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
        });
    }

    // --- Result Selection & Multi-Column Inspector Inspection ---

    private void onResultRowSelected() {
        int row = resultsTable.getSelectedRow();
        if (row < 0 || row >= results.size()) {
            clearInspector();
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(row);
        AuthTestResult_littlespidy selectedRes = results.get(modelRow);

        // Find all test configurations for this endpoint (same collection, method, and path)
        List<AuthTestResult_littlespidy> endpointResults = new ArrayList<>();
        for (AuthTestResult_littlespidy r : results) {
            if (r.getMethod().equalsIgnoreCase(selectedRes.getMethod())
                    && r.getPath().equalsIgnoreCase(selectedRes.getPath())
                    && r.getCollectionId().equals(selectedRes.getCollectionId())) {
                endpointResults.add(r);
            }
        }

        if (endpointResults.isEmpty()) {
            endpointResults.add(selectedRes);
        }

        columnsContainer.removeAll();
        columnViews.clear();

        for (AuthTestResult_littlespidy r : endpointResults) {
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
            long lat = r.getAuthLatencyMs();
            String info = (code > 0 ? code : "-") + " | " + len + " B | " + lat + " ms | " + r.getOutcome().name();

            Color colHeaderBg = null;
            if (r.getOutcome() == AuthTestOutcome_littlespidy.UNAUTHENTICATED_ACCESSIBLE) {
                colHeaderBg = new Color(255, 180, 70, 90);
            } else if (r.getOutcome() == AuthTestOutcome_littlespidy.SUCCESS || r.getOutcome() == AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY) {
                colHeaderBg = new Color(90, 225, 110, 90);
            } else if (r.getOutcome() == AuthTestOutcome_littlespidy.AUTH_REJECTED) {
                colHeaderBg = new Color(255, 120, 120, 90);
            } else {
                colHeaderBg = new Color(225, 238, 255);
            }

            ProfileColumnView colView = new ProfileColumnView(r.getProfileName(), info, colHeaderBg, reqComp, respComp);
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

    private void applyOutcomeFilter() {
        String sel = (String) outcomeFilterCombo.getSelectedItem();
        if (sel == null || "All Outcomes".equals(sel)) {
            resultsSorter.setRowFilter(null);
        } else if ("Unauthenticated Accessible".equals(sel)) {
            resultsSorter.setRowFilter(RowFilter.regexFilter("(?i)UNAUTHENTICATED_ACCESSIBLE", 6));
        } else if ("Authenticated Only".equals(sel)) {
            resultsSorter.setRowFilter(RowFilter.regexFilter("(?i)AUTHENTICATED_ONLY", 6));
        } else if ("Auth Rejected".equals(sel)) {
            resultsSorter.setRowFilter(RowFilter.regexFilter("(?i)AUTH_REJECTED", 6));
        } else if ("Success".equals(sel)) {
            resultsSorter.setRowFilter(RowFilter.regexFilter("(?i)SUCCESS", 6));
        } else if ("Errors".equals(sel)) {
            resultsSorter.setRowFilter(RowFilter.regexFilter("(?i)(ERROR|CLIENT_ERROR|SERVER_ERROR|NETWORK_ERROR)", 6));
        }
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
                fw.write("Collection,Method,Path,FullUrl,Profile,StatusCode,Length,Outcome,LatencyMs,Timestamp,Error\n");
                for (AuthTestResult_littlespidy r : results) {
                    fw.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,%d,\"%s\",%d,\"%s\",\"%s\"\n",
                            escapeCsv(r.getCollectionName()),
                            escapeCsv(r.getMethod()),
                            escapeCsv(r.getPath()),
                            escapeCsv(r.getFullUrl()),
                            escapeCsv(r.getProfileName()),
                            r.getAuthStatusCode(),
                            r.getAuthResponseLength(),
                            r.getOutcome().name(),
                            r.getAuthLatencyMs(),
                            dateFormat.format(new Date(r.getTimestamp())),
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
    }

    public List<AuthTestResult_littlespidy> getAllResults() {
        return results;
    }

    public void setResults(List<AuthTestResult_littlespidy> list) {
        results.clear();
        if (list != null) {
            results.addAll(list);
        }
        resultsTableModel.fireTableDataChanged();
    }

    // --- Table Models & Renderers ---

    private class ProfileTableModel extends AbstractTableModel {
        private final String[] columns = {"Test", "Profile Name", "Auth Type", "Credentials / Details"};

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
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            AuthProfile_littlespidy p = profiles.get(row);
            switch (col) {
                case 0: return activeProfileIds.contains(p.getId());
                case 1: return p.getName();
                case 2: return p.getAuthType().getDisplayName();
                case 3: return p.getMaskedSummary();
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

    private class ResultsTableModel extends AbstractTableModel {
        private final String[] columns = {"Collection", "Method", "Path", "Profile / Test Configuration", "Status Code", "Length", "Outcome", "Latency (ms)", "Time"};

        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            AuthTestResult_littlespidy r = results.get(row);
            switch (col) {
                case 0: return r.getCollectionName();
                case 1: return r.getMethod();
                case 2: return r.getPath();
                case 3: return r.getProfileName();
                case 4: return r.getAuthStatusCode() > 0 ? r.getAuthStatusCode() : "-";
                case 5: return r.getAuthResponseLength() > 0 ? r.getAuthResponseLength() + " B" : "-";
                case 6: return r.getOutcome().name();
                case 7: return r.getAuthLatencyMs();
                case 8: return dateFormat.format(new Date(r.getTimestamp()));
                default: return "";
            }
        }
    }

    private static class OutcomeCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (!isSelected && value != null) {
                String str = value.toString();
                if ("UNAUTHENTICATED_ACCESSIBLE".equalsIgnoreCase(str)) {
                    c.setForeground(new Color(204, 102, 0)); // Amber / Orange
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("AUTHENTICATED_ONLY".equalsIgnoreCase(str) || "SUCCESS".equalsIgnoreCase(str)) {
                    c.setForeground(new Color(0, 128, 0)); // Green
                    c.setFont(c.getFont().deriveFont(Font.PLAIN));
                } else if ("AUTH_REJECTED".equalsIgnoreCase(str)) {
                    c.setForeground(Color.RED);
                    c.setFont(c.getFont().deriveFont(Font.PLAIN));
                } else if ("NETWORK_ERROR".equalsIgnoreCase(str) || "SERVER_ERROR".equalsIgnoreCase(str)) {
                    c.setForeground(Color.MAGENTA);
                    c.setFont(c.getFont().deriveFont(Font.PLAIN));
                } else {
                    c.setForeground(table.getForeground());
                    c.setFont(c.getFont().deriveFont(Font.PLAIN));
                }
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
}
