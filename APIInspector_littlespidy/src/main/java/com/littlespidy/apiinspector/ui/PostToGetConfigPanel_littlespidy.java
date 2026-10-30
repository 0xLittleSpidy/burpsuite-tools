// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.apiinspector.model.*;
import com.littlespidy.apiinspector.ui.AuthAnalyzerConfigTab_littlespidy.CollectionComboItem;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration sub-panel for POST-to-GET method tampering testing.
 * Provides endpoint selection targeting POST endpoints and execution controls
 * matching the Auth Analyzer layout.
 */
public class PostToGetConfigPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private PostToGetTab_littlespidy postToGetTab;
    private APIInspectorTab_littlespidy rootTab;
    private APIImportTab_littlespidy importTabRef;

    // Endpoints Selection UI
    private JComboBox<CollectionComboItem> collectionSelectorCombo;
    private final EndpointSelectionTableModel_littlespidy endpointSelectionModel = new EndpointSelectionTableModel_littlespidy();
    private final JTable endpointSelectionTable = new JTable(endpointSelectionModel);
    private final JTextField endpointFilterField = new JTextField(16);

    // Execution Controls UI
    private final JComboBox<AuthProfileComboItem_littlespidy> authProfileCombo = new JComboBox<>();
    private final JTextField sessionHeaderField = new JTextField(18);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 30, 1));
    private final JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 10000, 10));
    private final JTextField runnerNameField = new JTextField("POST to GET Runner 1", 14);

    private JButton attackAllEndpointsBtn;
    private JButton attackSelectedBtn;
    private JButton pauseBtn;
    private JButton cancelBtn;
    private JProgressBar progressBar;
    private JLabel progressStatusLabel;

    private int runnerCount = 1;

    public PostToGetConfigPanel_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;

        setBorder(new EmptyBorder(6, 6, 6, 6));
        initComponents();
    }

    public void setPostToGetTab(PostToGetTab_littlespidy tab) {
        this.postToGetTab = tab;
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.rootTab = rootTab;
    }

    public void setImportTabRef(APIImportTab_littlespidy importTabRef) {
        this.importTabRef = importTabRef;
        refreshCollectionsCombo();
    }

    public void updateAvailableProfiles(List<AuthProfile_littlespidy> profiles) {
        authProfileCombo.removeAllItems();
        authProfileCombo.addItem(new AuthProfileComboItem_littlespidy(null, "[No Auth / Unauthenticated]"));
        if (profiles != null) {
            for (AuthProfile_littlespidy p : profiles) {
                authProfileCombo.addItem(new AuthProfileComboItem_littlespidy(p, p.getName() + " (" + p.getMaskedSummary() + ")"));
            }
        }
    }

    public int getThreadCount() {
        return (Integer) threadSpinner.getValue();
    }

    public void setThreadCount(int count) {
        threadSpinner.setValue(Math.max(1, count));
    }

    public int getDelayMs() {
        return (Integer) delaySpinner.getValue();
    }

    public void setDelayMs(int delay) {
        delaySpinner.setValue(Math.max(0, delay));
    }

    private void initComponents() {
        // Center: Endpoints to Test Panel
        JPanel endpointsPanel = new JPanel(new BorderLayout(4, 4));
        endpointsPanel.setBorder(new TitledBorder("Endpoints to Test (POST Requests)"));

        JPanel colSelectBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        colSelectBar.add(new JLabel("Collection:"));
        collectionSelectorCombo = new JComboBox<>();
        collectionSelectorCombo.setPreferredSize(new Dimension(280, 24));
        collectionSelectorCombo.addActionListener(e -> onCollectionSelectionChanged());
        colSelectBar.add(collectionSelectorCombo);

        JButton reloadColsBtn = new JButton("Refresh");
        reloadColsBtn.setToolTipText("Reload collections from API Import tab");
        reloadColsBtn.addActionListener(e -> refreshCollectionsCombo());
        colSelectBar.add(reloadColsBtn);

        colSelectBar.add(new JLabel("Filter:"));
        endpointFilterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { endpointSelectionModel.applyFilter(endpointFilterField.getText()); }
            @Override public void removeUpdate(DocumentEvent e) { endpointSelectionModel.applyFilter(endpointFilterField.getText()); }
            @Override public void changedUpdate(DocumentEvent e) { endpointSelectionModel.applyFilter(endpointFilterField.getText()); }
        });
        colSelectBar.add(endpointFilterField);

        JButton selectAllEpBtn = new JButton("Select All");
        selectAllEpBtn.addActionListener(e -> endpointSelectionModel.selectAll(true));
        JButton deselectAllEpBtn = new JButton("Deselect All");
        deselectAllEpBtn.addActionListener(e -> endpointSelectionModel.selectAll(false));
        colSelectBar.add(selectAllEpBtn);
        colSelectBar.add(deselectAllEpBtn);
        endpointsPanel.add(colSelectBar, BorderLayout.NORTH);

        endpointSelectionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointSelectionTable.getColumnModel().getColumn(0).setMaxWidth(40);
        endpointSelectionTable.getColumnModel().getColumn(1).setMaxWidth(75);
        endpointSelectionTable.getColumnModel().getColumn(2).setPreferredWidth(220);
        endpointSelectionTable.getColumnModel().getColumn(3).setPreferredWidth(250);
        endpointSelectionTable.getColumnModel().getColumn(4).setMaxWidth(90);

        endpointSelectionTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_SPACE) {
                    int[] rows = endpointSelectionTable.getSelectedRows();
                    if (rows.length > 0) {
                        int firstModelRow = endpointSelectionTable.convertRowIndexToModel(rows[0]);
                        List<EndpointSelectionItem_littlespidy> items = endpointSelectionModel.getDisplayedItems();
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
        endpointsPanel.add(new JScrollPane(endpointSelectionTable), BorderLayout.CENTER);

        add(endpointsPanel, BorderLayout.CENTER);

        // Bottom: Execution Controls Panel (Matching Auth Analyzer)
        JPanel execControlsPanel = new JPanel();
        execControlsPanel.setLayout(new BoxLayout(execControlsPanel, BoxLayout.Y_AXIS));
        execControlsPanel.setBorder(new TitledBorder("Execution Controls"));

        JPanel singleLineControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));

        singleLineControls.add(new JLabel("Auth Profile:"));
        authProfileCombo.setPreferredSize(new Dimension(180, 24));
        authProfileCombo.addItem(new AuthProfileComboItem_littlespidy(null, "[No Auth / Unauthenticated]"));
        authProfileCombo.addActionListener(e -> onAuthProfileSelectionChanged());
        singleLineControls.add(authProfileCombo);

        singleLineControls.add(new JLabel("Auth Header:"));
        sessionHeaderField.setPreferredSize(new Dimension(140, 24));
        sessionHeaderField.setToolTipText("Enter raw auth header (e.g. Authorization: Bearer <token>)");
        singleLineControls.add(sessionHeaderField);

        singleLineControls.add(new JLabel("Threads:"));
        threadSpinner.setPreferredSize(new Dimension(55, 24));
        singleLineControls.add(threadSpinner);

        singleLineControls.add(new JLabel("Delay (ms):"));
        delaySpinner.setPreferredSize(new Dimension(65, 24));
        singleLineControls.add(delaySpinner);

        singleLineControls.add(new JLabel("Runner:"));
        runnerNameField.setPreferredSize(new Dimension(140, 24));
        singleLineControls.add(runnerNameField);

        attackAllEndpointsBtn = new JButton("Attack");
        attackAllEndpointsBtn.setFont(attackAllEndpointsBtn.getFont().deriveFont(Font.BOLD));
        attackAllEndpointsBtn.addActionListener(e -> {
            endpointSelectionModel.selectAll(true);
            launchAttackForSelectedEndpoints();
        });
        singleLineControls.add(attackAllEndpointsBtn);

        attackSelectedBtn = new JButton("Test Selected");
        attackSelectedBtn.addActionListener(e -> launchAttackForSelectedEndpoints());
        singleLineControls.add(attackSelectedBtn);

        pauseBtn = new JButton("Pause");
        pauseBtn.setEnabled(false);
        pauseBtn.addActionListener(e -> onTogglePause());
        singleLineControls.add(pauseBtn);

        cancelBtn = new JButton("Cancel");
        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> onCancelAttack());
        singleLineControls.add(cancelBtn);

        execControlsPanel.add(singleLineControls);

        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        progressBar.setAlignmentX(Component.CENTER_ALIGNMENT);
        execControlsPanel.add(progressBar);

        progressStatusLabel = new JLabel("Ready");
        progressStatusLabel.setFont(progressStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        progressStatusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        progressStatusLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        execControlsPanel.add(progressStatusLabel);

        add(execControlsPanel, BorderLayout.SOUTH);
    }

    private void onAuthProfileSelectionChanged() {
        AuthProfileComboItem_littlespidy sel = (AuthProfileComboItem_littlespidy) authProfileCombo.getSelectedItem();
        if (sel != null && sel.profile != null) {
            AuthProfile_littlespidy p = sel.profile;
            String headerStr = p.getFormattedHeaderString();
            if (headerStr != null && !headerStr.isBlank()) {
                sessionHeaderField.setText(headerStr);
            }
        }
    }

    public void refreshCollectionsCombo() {
        ImportedCollection_littlespidy prevSelected = null;
        CollectionComboItem sel = (CollectionComboItem) collectionSelectorCombo.getSelectedItem();
        if (sel != null && sel.collection != null) {
            prevSelected = sel.collection;
        } else if (importTabRef != null && importTabRef.getSelectedCollection() != null) {
            prevSelected = importTabRef.getSelectedCollection();
        }

        collectionSelectorCombo.removeAllItems();
        if (importTabRef != null) {
            List<ImportedCollection_littlespidy> allCols = new ArrayList<>(importTabRef.getAllCollections());
            allCols.sort((a, b) -> String.CASE_INSENSITIVE_ORDER.compare(
                    a.getName() != null ? a.getName() : "",
                    b.getName() != null ? b.getName() : ""));
            collectionSelectorCombo.addItem(new CollectionComboItem(null, "[All Imported Collections]"));
            for (ImportedCollection_littlespidy c : allCols) {
                collectionSelectorCombo.addItem(new CollectionComboItem(c, c.getName() + " (" + c.getEndpointCount() + ")"));
            }
        }
        if (prevSelected != null) {
            selectCollection(prevSelected);
        } else {
            onCollectionSelectionChanged();
        }
    }

    public void selectCollection(ImportedCollection_littlespidy col) {
        if (collectionSelectorCombo == null) return;
        if (col == null) {
            if (collectionSelectorCombo.getItemCount() > 0) {
                collectionSelectorCombo.setSelectedIndex(0);
            }
            return;
        }
        for (int i = 0; i < collectionSelectorCombo.getItemCount(); i++) {
            CollectionComboItem item = collectionSelectorCombo.getItemAt(i);
            if (item != null && item.collection != null) {
                boolean matches = false;
                if (item.collection == col) {
                    matches = true;
                } else if (item.collection.getId() != null && col.getId() != null && item.collection.getId().equals(col.getId())) {
                    matches = true;
                } else if (item.collection.getName() != null && col.getName() != null && item.collection.getName().equals(col.getName())) {
                    matches = true;
                }
                if (matches) {
                    collectionSelectorCombo.setSelectedIndex(i);
                    return;
                }
            }
        }
    }

    private void onCollectionSelectionChanged() {
        CollectionComboItem sel = (CollectionComboItem) collectionSelectorCombo.getSelectedItem();
        if (sel == null || sel.collection == null) {
            if (importTabRef != null) {
                List<EndpointSelectionItem_littlespidy> all = new ArrayList<>();
                for (ImportedCollection_littlespidy c : importTabRef.getAllCollections()) {
                    for (DiscoveredEndpoint_littlespidy ep : c.getEndpoints()) {
                        boolean isPost = "POST".equalsIgnoreCase(ep.getMethod());
                        all.add(new EndpointSelectionItem_littlespidy(c, ep, isPost));
                    }
                }
                endpointSelectionModel.setItems(all);
            } else {
                endpointSelectionModel.setItems(Collections.emptyList());
            }
        } else {
            List<EndpointSelectionItem_littlespidy> items = new ArrayList<>();
            for (DiscoveredEndpoint_littlespidy ep : sel.collection.getEndpoints()) {
                boolean isPost = "POST".equalsIgnoreCase(ep.getMethod());
                items.add(new EndpointSelectionItem_littlespidy(sel.collection, ep, isPost));
            }
            endpointSelectionModel.setItems(items);
        }
        endpointSelectionModel.applyFilter(endpointFilterField.getText());
    }

    private void launchAttackForSelectedEndpoints() {
        if (postToGetTab == null || rootTab == null) return;

        List<EndpointSelectionItem_littlespidy> selectedEndpoints = endpointSelectionModel.getSelectedItems();
        if (selectedEndpoints.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select at least one endpoint to test.", "No Endpoints Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String runnerName = runnerNameField.getText().trim();
        if (runnerName.isEmpty()) {
            runnerName = "POST to GET Runner " + (++runnerCount);
        }

        AuthProfileComboItem_littlespidy authSel = (AuthProfileComboItem_littlespidy) authProfileCombo.getSelectedItem();
        AuthProfile_littlespidy profile = authSel != null ? authSel.profile : null;
        String customAuthHeader = sessionHeaderField.getText().trim();

        setExecutionUIState(true);
        rootTab.selectTab(postToGetTab);

        postToGetTab.executeAttack(
                selectedEndpoints,
                null,
                profile,
                customAuthHeader,
                getThreadCount(),
                getDelayMs(),
                runnerName
        );

        runnerNameField.setText("POST to GET Runner " + (++runnerCount));
    }

    private void onTogglePause() {
        if (postToGetTab != null && postToGetTab.getEngine() != null) {
            var eng = postToGetTab.getEngine();
            if (eng.isPaused()) {
                eng.resume();
                pauseBtn.setText("Pause");
                progressStatusLabel.setText("Resumed POST-to-GET test run...");
            } else {
                eng.pause();
                pauseBtn.setText("Resume");
                progressStatusLabel.setText("Paused POST-to-GET test run");
            }
        }
    }

    private void onCancelAttack() {
        if (postToGetTab != null && postToGetTab.getEngine() != null) {
            postToGetTab.getEngine().cancel();
        }
        progressStatusLabel.setText("Cancelling POST-to-GET test run...");
        cancelBtn.setEnabled(false);
    }

    public void setExecutionUIState(boolean running) {
        attackAllEndpointsBtn.setEnabled(!running);
        attackSelectedBtn.setEnabled(!running);
        cancelBtn.setEnabled(running);
        if (pauseBtn != null) {
            pauseBtn.setEnabled(running);
            pauseBtn.setText("Pause");
        }
        progressBar.setVisible(running);
    }

    public void updateProgress(int completedCount, int totalCount, String status) {
        progressBar.setMaximum(totalCount);
        progressBar.setValue(completedCount);
        progressStatusLabel.setText(status);
    }

    public void onAttackFinished(boolean cancelled, int totalCompleted) {
        setExecutionUIState(false);
        if (cancelled) {
            progressStatusLabel.setText("POST-to-GET test run cancelled. Total completed: " + totalCompleted);
        } else {
            progressStatusLabel.setText("POST-to-GET test run finished. Total completed: " + totalCompleted);
        }
    }
}
