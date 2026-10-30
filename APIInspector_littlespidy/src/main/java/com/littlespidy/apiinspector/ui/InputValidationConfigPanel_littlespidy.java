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
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Configuration sub-panel for Input Validation testing and fuzzing.
 * Tier 1: Input Validation payloads table (without Action column).
 * Tier 2: Endpoints to Test panel with alphabetically sorted API collections.
 * Tier 3: Execution controls matching Auth Analyzer layout with Threads, Delay,
 * Runner name, Attack, Test Selected, Pause/Resume, and Cancel buttons.
 */
public class InputValidationConfigPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private InputValidationTab_littlespidy inputValidationTab;
    private APIInspectorTab_littlespidy rootTab;
    private APIImportTab_littlespidy importTabRef;

    // Payloads Table UI
    private final List<InputValidationPayloadItem_littlespidy> allPayloads = new ArrayList<>();
    private final List<InputValidationPayloadItem_littlespidy> displayedPayloads = new ArrayList<>();
    private final PayloadTableModel payloadTableModel = new PayloadTableModel();
    private final JTable payloadsTable = new JTable(payloadTableModel);
    private final JComboBox<String> categoryFilterCombo = new JComboBox<>();
    private final JTextField payloadSearchField = new JTextField(12);
    private final JLabel payloadCountLabel = new JLabel("0 payloads (0 enabled)");

    // Endpoints Selection UI
    private JComboBox<CollectionComboItem> collectionSelectorCombo;
    private final EndpointSelectionTableModel_littlespidy endpointSelectionModel = new EndpointSelectionTableModel_littlespidy();
    private final JTable endpointSelectionTable = new JTable(endpointSelectionModel);
    private final JTextField endpointFilterField = new JTextField(16);

    // Execution Controls UI
    private final JComboBox<AuthProfileComboItem_littlespidy> authProfileCombo = new JComboBox<>();
    private final JTextField sessionHeaderField = new JTextField(18);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 30, 1));
    private final JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 10000, 10));
    private final JTextField runnerNameField = new JTextField("Input Validation Runner 1", 14);

    private JButton attackAllEndpointsBtn;
    private JButton attackSelectedBtn;
    private JButton pauseBtn;
    private JButton cancelBtn;
    private JProgressBar progressBar;
    private JLabel progressStatusLabel;

    private int runnerCount = 1;

    public InputValidationConfigPanel_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.allPayloads.addAll(NaughtyStringsParser_littlespidy.loadAllIndividualPayloads());
        this.displayedPayloads.addAll(allPayloads);

        setBorder(new EmptyBorder(6, 6, 6, 6));
        initComponents();
    }

    public void setInputValidationTab(InputValidationTab_littlespidy tab) {
        this.inputValidationTab = tab;
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

    public List<InputValidationPayloadItem_littlespidy> getPayloads() {
        return new ArrayList<>(allPayloads);
    }

    public List<InputValidationPayloadItem_littlespidy> getPayloadItems() {
        return getPayloads();
    }

    public void setPayloads(List<InputValidationPayloadItem_littlespidy> newPayloads) {
        allPayloads.clear();
        if (newPayloads != null) {
            allPayloads.addAll(newPayloads);
        } else {
            allPayloads.addAll(NaughtyStringsParser_littlespidy.loadAllIndividualPayloads());
        }
        applyFilter();
    }

    public void setPayloadItems(List<InputValidationPayloadItem_littlespidy> items) {
        setPayloads(items);
    }

    public EndpointSelectionTableModel_littlespidy getEndpointSelectionModel() {
        return endpointSelectionModel;
    }

    public List<InputValidationTechnique_littlespidy> getTechniques() {
        return InputValidationTechnique_littlespidy.getDefaultTechniques();
    }

    public void setTechniques(List<InputValidationTechnique_littlespidy> techs) {
    }

    public String getTargetEndpoint() {
        return "";
    }

    public void setTargetEndpoint(String target) {
    }

    private void initComponents() {
        JPanel centerContainer = new JPanel(new BorderLayout(4, 4));

        // 1. Tier 1 (Top): Payloads Table Panel
        JPanel payloadsPanel = new JPanel(new BorderLayout(4, 4));
        payloadsPanel.setBorder(new TitledBorder("Input Validation & Fuzzing Payloads"));

        JPanel payloadToolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        categoryFilterCombo.addItem("All Payloads");
        categoryFilterCombo.addItem("BLNS: Reserved Identifiers");
        categoryFilterCombo.addItem("BLNS: Numeric Boundaries & Extremes");
        categoryFilterCombo.addItem("BLNS: Special Characters & Quotations");
        categoryFilterCombo.addItem("BLNS: Unicode & Encoding Quirks");
        categoryFilterCombo.addItem("BLNS: Format Strings & Unwanted Interpolation");
        categoryFilterCombo.addItem("Custom Wordlists");
        categoryFilterCombo.addActionListener(e -> applyFilter());
        payloadToolBar.add(new JLabel("Category:"));
        payloadToolBar.add(categoryFilterCombo);

        payloadSearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        payloadToolBar.add(new JLabel("Search:"));
        payloadToolBar.add(payloadSearchField);

        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> {
            for (InputValidationPayloadItem_littlespidy item : displayedPayloads) {
                item.setEnabled(true);
            }
            payloadTableModel.fireTableDataChanged();
            updatePayloadCountLabel();
        });
        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> {
            for (InputValidationPayloadItem_littlespidy item : displayedPayloads) {
                item.setEnabled(false);
            }
            payloadTableModel.fireTableDataChanged();
            updatePayloadCountLabel();
        });
        payloadToolBar.add(selectAllBtn);
        payloadToolBar.add(deselectAllBtn);
        payloadToolBar.add(payloadCountLabel);

        payloadsPanel.add(payloadToolBar, BorderLayout.NORTH);

        payloadsTable.setFillsViewportHeight(true);
        payloadsTable.setRowHeight(24);
        payloadsTable.getColumnModel().getColumn(0).setMaxWidth(60);
        payloadsTable.getColumnModel().getColumn(1).setMaxWidth(70);
        payloadsTable.getColumnModel().getColumn(2).setPreferredWidth(160);
        payloadsTable.getColumnModel().getColumn(3).setPreferredWidth(450);

        payloadsPanel.add(new JScrollPane(payloadsTable), BorderLayout.CENTER);

        // 2. Tier 2 (Middle): Endpoints to Test Panel
        JPanel endpointsPanel = new JPanel(new BorderLayout(4, 4));
        endpointsPanel.setBorder(new TitledBorder("Endpoints to Test (Imported API Collections)"));

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

        // Split Payloads (top) and Endpoints (middle)
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, payloadsPanel, endpointsPanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);
        centerContainer.add(splitPane, BorderLayout.CENTER);

        add(centerContainer, BorderLayout.CENTER);

        // 3. Tier 3 (Bottom): Execution Controls Panel (Matching Auth Analyzer)
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
        updatePayloadCountLabel();
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

    private void applyFilter() {
        String selectedCategory = (String) categoryFilterCombo.getSelectedItem();
        String search = payloadSearchField.getText().trim().toLowerCase(Locale.ROOT);
        displayedPayloads.clear();
        for (InputValidationPayloadItem_littlespidy item : allPayloads) {
            boolean catMatch = selectedCategory == null || "All Categories".equals(selectedCategory)
                    || item.getCategory().equalsIgnoreCase(selectedCategory);
            boolean searchMatch = search.isEmpty() || item.getPayload().toLowerCase(Locale.ROOT).contains(search)
                    || item.getId().toLowerCase(Locale.ROOT).contains(search);
            if (catMatch && searchMatch) {
                displayedPayloads.add(item);
            }
        }
        payloadTableModel.fireTableDataChanged();
        updatePayloadCountLabel();
    }

    private void updatePayloadCountLabel() {
        int total = allPayloads.size();
        int enabled = 0;
        for (InputValidationPayloadItem_littlespidy item : allPayloads) {
            if (item.isEnabled()) enabled++;
        }
        payloadCountLabel.setText(total + " payloads (" + enabled + " enabled)");
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
        if (collectionSelectorCombo == null) {
            return;
        }
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
                        all.add(new EndpointSelectionItem_littlespidy(c, ep, true));
                    }
                }
                endpointSelectionModel.setItems(all);
            } else {
                endpointSelectionModel.setItems(Collections.emptyList());
            }
        } else {
            List<EndpointSelectionItem_littlespidy> items = new ArrayList<>();
            for (DiscoveredEndpoint_littlespidy ep : sel.collection.getEndpoints()) {
                items.add(new EndpointSelectionItem_littlespidy(sel.collection, ep, true));
            }
            endpointSelectionModel.setItems(items);
        }
        endpointSelectionModel.applyFilter(endpointFilterField.getText());
    }

    private void launchAttackForSelectedEndpoints() {
        if (inputValidationTab == null || rootTab == null) return;

        List<EndpointSelectionItem_littlespidy> selectedEndpoints = endpointSelectionModel.getSelectedItems();
        if (selectedEndpoints.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select at least one endpoint to test.", "No Endpoints Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String runnerName = runnerNameField.getText().trim();
        if (runnerName.isEmpty()) {
            runnerName = "Input Validation Runner " + (++runnerCount);
        }

        AuthProfileComboItem_littlespidy authSel = (AuthProfileComboItem_littlespidy) authProfileCombo.getSelectedItem();
        AuthProfile_littlespidy profile = authSel != null ? authSel.profile : null;
        String customAuthHeader = sessionHeaderField.getText().trim();

        List<InputValidationPayloadItem_littlespidy> activePayloads = new ArrayList<>();
        for (InputValidationPayloadItem_littlespidy p : allPayloads) {
            if (p.isEnabled()) activePayloads.add(p);
        }

        setExecutionUIState(true);
        rootTab.selectTab(inputValidationTab);

        inputValidationTab.executeAttack(
                selectedEndpoints,
                null,
                profile,
                customAuthHeader,
                activePayloads,
                getThreadCount(),
                getDelayMs(),
                runnerName
        );

        runnerNameField.setText("Input Validation Runner " + (++runnerCount));
    }

    private void onTogglePause() {
        if (inputValidationTab != null && inputValidationTab.getInputValidationEngine() != null) {
            var eng = inputValidationTab.getInputValidationEngine();
            if (eng.isPaused()) {
                eng.resume();
                pauseBtn.setText("Pause");
                progressStatusLabel.setText("Resumed Input Validation test run...");
            } else {
                eng.pause();
                pauseBtn.setText("Resume");
                progressStatusLabel.setText("Paused Input Validation test run");
            }
        }
    }

    private void onCancelAttack() {
        if (inputValidationTab != null && inputValidationTab.getInputValidationEngine() != null) {
            inputValidationTab.getInputValidationEngine().cancel();
        }
        progressStatusLabel.setText("Cancelling Input Validation test run...");
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
            progressStatusLabel.setText("Input Validation test run cancelled. Total completed: " + totalCompleted);
        } else {
            progressStatusLabel.setText("Input Validation test run finished. Total completed: " + totalCompleted);
        }
    }

    private class PayloadTableModel extends AbstractTableModel {
        private final String[] columns = {"Enable", "ID", "Category", "Payload Value"};

        @Override
        public int getRowCount() {
            return displayedPayloads.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Boolean.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= displayedPayloads.size()) return "";
            InputValidationPayloadItem_littlespidy item = displayedPayloads.get(rowIndex);
            switch (columnIndex) {
                case 0: return item.isEnabled();
                case 1: return item.getId();
                case 2: return item.getCategory();
                case 3: return item.getPayload();
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= displayedPayloads.size()) return;
            InputValidationPayloadItem_littlespidy item = displayedPayloads.get(rowIndex);
            if (columnIndex == 0 && aValue instanceof Boolean) {
                item.setEnabled((Boolean) aValue);
                fireTableCellUpdated(rowIndex, columnIndex);
                updatePayloadCountLabel();
            }
        }
    }
}
