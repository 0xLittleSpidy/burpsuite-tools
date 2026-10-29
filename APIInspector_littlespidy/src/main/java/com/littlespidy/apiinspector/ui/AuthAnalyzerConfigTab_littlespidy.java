// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DragSource;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Dedicated Configuration Tab for Auth Analyzer.
 * Houses Authentication Profiles management, Endpoints selection, and Attack execution controls.
 */
public class AuthAnalyzerConfigTab_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final AuthTestingTab_littlespidy authTestingTab;
    private APIInspectorTab_littlespidy rootTab;
    private APIImportTab_littlespidy importTabRef;

    private final List<AuthProfile_littlespidy> profiles = new ArrayList<>();
    private final Set<String> activeProfileIds = new HashSet<>();
    private final List<Runnable> stateChangedListeners = new ArrayList<>();

    // Profiles UI
    private ProfileTableModel profileTableModel;
    private JTable profileTable;

    // Endpoints Selection UI
    private JComboBox<CollectionComboItem> collectionSelectorCombo;
    private EndpointSelectionTableModel endpointSelectionModel;
    private JTable endpointSelectionTable;

    // Execution Controls UI
    private JButton attackBtn;
    private JButton testSelectedBtn;
    private JButton cancelBtn;
    private JSpinner threadSpinner;
    private JSpinner delaySpinner;
    private JTextField runnerNameField;
    private JProgressBar progressBar;
    private JLabel progressStatusLabel;

    private int runnerCounter = 1;

    public AuthAnalyzerConfigTab_littlespidy(MontoyaApi api, AuthTestingTab_littlespidy authTestingTab) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.authTestingTab = authTestingTab;

        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.rootTab = rootTab;
    }

    public void setImportTabRef(APIImportTab_littlespidy importTabRef) {
        this.importTabRef = importTabRef;
    }

    public void addStateChangedListener(Runnable listener) {
        if (listener != null) {
            this.stateChangedListeners.add(listener);
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
        JPanel mainPanel = new JPanel(new BorderLayout(6, 6));

        // 1. Top Section: Profiles Management
        JPanel profilesPanel = new JPanel(new BorderLayout(4, 4));
        profilesPanel.setBorder(new TitledBorder("Authentication Profiles"));

        profileTableModel = new ProfileTableModel();
        profileTable = new JTable(profileTableModel);
        profileTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        profileTable.getColumnModel().getColumn(0).setMaxWidth(45);
        profileTable.getColumnModel().getColumn(0).setPreferredWidth(45);
        if (!GraphicsEnvironment.isHeadless()) {
            profileTable.setDragEnabled(true);
            profileTable.setDropMode(DropMode.INSERT_ROWS);
            profileTable.setTransferHandler(new TableRowTransferHandler());
        }
        profileTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_SPACE) {
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
                        if (authTestingTab != null) {
                            authTestingTab.onProfilesUpdated();
                        }
                        notifyStateChanged();
                        e.consume();
                    }
                }
            }
        });

        JScrollPane profileScroll = new JScrollPane(profileTable);
        profileScroll.setPreferredSize(new Dimension(500, 150));
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
        JButton moveUpBtn = new JButton("Move Up");
        moveUpBtn.setToolTipText("Move selected profile up");
        moveUpBtn.addActionListener(e -> onMoveProfileUp());
        JButton moveDownBtn = new JButton("Move Down");
        moveDownBtn.setToolTipText("Move selected profile down");
        moveDownBtn.addActionListener(e -> onMoveProfileDown());

        profileActions.add(addProfBtn);
        profileActions.add(editProfBtn);
        profileActions.add(dupProfBtn);
        profileActions.add(delProfBtn);
        profileActions.add(moveUpBtn);
        profileActions.add(moveDownBtn);
        profilesPanel.add(profileActions, BorderLayout.SOUTH);

        // 2. Center Section: Collection & Endpoints Selection Panel
        JPanel endpointsPanel = new JPanel(new BorderLayout(4, 4));
        endpointsPanel.setBorder(new TitledBorder("Endpoints to Test"));

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
        endpointsPanel.add(colSelectBar, BorderLayout.NORTH);

        endpointSelectionModel = new EndpointSelectionTableModel();
        endpointSelectionTable = new JTable(endpointSelectionModel);
        endpointSelectionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointSelectionTable.getColumnModel().getColumn(0).setMaxWidth(40);
        endpointSelectionTable.getColumnModel().getColumn(1).setMaxWidth(70);
        endpointSelectionTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_SPACE) {
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

        // Split Profiles (top) and Endpoints (center)
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, profilesPanel, endpointsPanel);
        splitPane.setResizeWeight(0.35);
        splitPane.setContinuousLayout(true);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        // 3. Bottom Section: Execution Controls Panel (Single Line Controls)
        JPanel execControlsPanel = new JPanel();
        execControlsPanel.setLayout(new BoxLayout(execControlsPanel, BoxLayout.Y_AXIS));
        execControlsPanel.setBorder(new TitledBorder("Execution Controls"));

        JPanel singleLineControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));
        singleLineControls.add(new JLabel("Threads:"));
        threadSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 20, 1));
        threadSpinner.setPreferredSize(new Dimension(55, 24));
        singleLineControls.add(threadSpinner);

        singleLineControls.add(new JLabel("Delay (ms):"));
        delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 5000, 25));
        delaySpinner.setPreferredSize(new Dimension(65, 24));
        singleLineControls.add(delaySpinner);

        singleLineControls.add(new JLabel("Runner:"));
        runnerNameField = new JTextField("Runner " + runnerCounter, 12);
        runnerNameField.setPreferredSize(new Dimension(130, 24));
        singleLineControls.add(runnerNameField);

        attackBtn = new JButton("Attack");
        attackBtn.setFont(attackBtn.getFont().deriveFont(Font.BOLD));
        attackBtn.addActionListener(e -> onAttackAll());
        singleLineControls.add(attackBtn);

        testSelectedBtn = new JButton("Test Selected");
        testSelectedBtn.addActionListener(e -> onAttackSelected());
        singleLineControls.add(testSelectedBtn);

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

        mainPanel.add(execControlsPanel, BorderLayout.SOUTH);
        add(mainPanel, BorderLayout.CENTER);
    }

    // --- Profile Management Actions ---

    private void onNewProfile() {
        AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(
                SwingUtilities.getWindowAncestor(this), "New Authentication Profile", null, newProfile -> {
            profiles.add(newProfile);
            activeProfileIds.add(newProfile.getId());
            profileTableModel.fireTableDataChanged();
            if (authTestingTab != null) {
                authTestingTab.onProfilesUpdated();
            }
            notifyStateChanged();
        });
        if (!GraphicsEnvironment.isHeadless()) {
            dialog.setVisible(true);
        }
    }

    private void onEditProfile() {
        int row = profileTable.getSelectedRow();
        if (row < 0 || row >= profiles.size()) {
            JOptionPane.showMessageDialog(this, "Please select a profile to edit.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = profileTable.convertRowIndexToModel(row);
        AuthProfile_littlespidy profile = profiles.get(modelRow);

        AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(
                SwingUtilities.getWindowAncestor(this), "Edit Authentication Profile", profile, updatedProfile -> {
            profileTableModel.fireTableRowsUpdated(modelRow, modelRow);
            if (authTestingTab != null) {
                authTestingTab.onProfilesUpdated();
            }
            notifyStateChanged();
        });
        if (!GraphicsEnvironment.isHeadless()) {
            dialog.setVisible(true);
        }
    }

    private void onDuplicateProfile() {
        int row = profileTable.getSelectedRow();
        if (row < 0 || row >= profiles.size()) {
            JOptionPane.showMessageDialog(this, "Please select a profile to duplicate.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = profileTable.convertRowIndexToModel(row);
        AuthProfile_littlespidy original = profiles.get(modelRow);
        AuthProfile_littlespidy copy = original.copy();
        profiles.add(copy);
        activeProfileIds.add(copy.getId());
        profileTableModel.fireTableDataChanged();
        if (authTestingTab != null) {
            authTestingTab.onProfilesUpdated();
        }
        notifyStateChanged();
    }

    private void onDeleteProfile() {
        int row = profileTable.getSelectedRow();
        if (row < 0 || row >= profiles.size()) {
            JOptionPane.showMessageDialog(this, "Please select a profile to delete.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = profileTable.convertRowIndexToModel(row);
        AuthProfile_littlespidy profile = profiles.get(modelRow);
        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to delete profile '" + profile.getName() + "'?",
                "Confirm Delete", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            profiles.remove(modelRow);
            activeProfileIds.remove(profile.getId());
            profileTableModel.fireTableDataChanged();
            if (authTestingTab != null) {
                authTestingTab.onProfilesUpdated();
            }
            notifyStateChanged();
        }
    }

    private void onMoveProfileUp() {
        int sel = profileTable.getSelectedRow();
        if (sel <= 0 || sel >= profiles.size()) return;
        int modelIdx = profileTable.convertRowIndexToModel(sel);
        Collections.swap(profiles, modelIdx, modelIdx - 1);
        profileTableModel.fireTableDataChanged();
        int newSel = profileTable.convertRowIndexToView(modelIdx - 1);
        profileTable.setRowSelectionInterval(newSel, newSel);
        if (authTestingTab != null) {
            authTestingTab.onProfilesUpdated();
        }
        notifyStateChanged();
    }

    private void onMoveProfileDown() {
        int sel = profileTable.getSelectedRow();
        if (sel < 0 || sel >= profiles.size() - 1) return;
        int modelIdx = profileTable.convertRowIndexToModel(sel);
        Collections.swap(profiles, modelIdx, modelIdx + 1);
        profileTableModel.fireTableDataChanged();
        int newSel = profileTable.convertRowIndexToView(modelIdx + 1);
        profileTable.setRowSelectionInterval(newSel, newSel);
        if (authTestingTab != null) {
            authTestingTab.onProfilesUpdated();
        }
        notifyStateChanged();
    }

    private class TableRowTransferHandler extends TransferHandler {
        private final DataFlavor localObjectFlavor = new DataFlavor(Integer.class, "Integer Row Index");
        private int sourceRow = -1;

        @Override
        protected Transferable createTransferable(JComponent c) {
            sourceRow = profileTable.getSelectedRow();
            return new Transferable() {
                @Override
                public DataFlavor[] getTransferDataFlavors() {
                    return new DataFlavor[]{localObjectFlavor};
                }

                @Override
                public boolean isDataFlavorSupported(DataFlavor flavor) {
                    return localObjectFlavor.equals(flavor);
                }

                @Override
                public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
                    if (isDataFlavorSupported(flavor)) {
                        return sourceRow;
                    }
                    throw new UnsupportedFlavorException(flavor);
                }
            };
        }

        @Override
        public int getSourceActions(JComponent c) {
            return TransferHandler.MOVE;
        }

        @Override
        public boolean canImport(TransferSupport support) {
            boolean can = support.isDrop() && support.isDataFlavorSupported(localObjectFlavor);
            profileTable.setCursor(can ? DragSource.DefaultMoveDrop : DragSource.DefaultMoveNoDrop);
            return can;
        }

        @Override
        public boolean importData(TransferSupport support) {
            if (!canImport(support)) return false;
            JTable.DropLocation dl = (JTable.DropLocation) support.getDropLocation();
            int dropTargetRow = dl.getRow();
            int max = profiles.size();
            if (dropTargetRow < 0 || dropTargetRow > max) {
                dropTargetRow = max;
            }

            try {
                Object data = support.getTransferable().getTransferData(localObjectFlavor);
                if (!(data instanceof Integer)) return false;
                int sourceViewRow = (Integer) data;
                if (sourceViewRow < 0 || sourceViewRow >= profiles.size()) return false;
                int sourceModelRow = profileTable.convertRowIndexToModel(sourceViewRow);

                AuthProfile_littlespidy moved = profiles.remove(sourceModelRow);
                int targetIndex = dropTargetRow;
                if (targetIndex > sourceModelRow) {
                    targetIndex--;
                }
                if (targetIndex < 0) targetIndex = 0;
                if (targetIndex > profiles.size()) targetIndex = profiles.size();
                profiles.add(targetIndex, moved);

                profileTableModel.fireTableDataChanged();
                int newViewRow = profileTable.convertRowIndexToView(targetIndex);
                profileTable.setRowSelectionInterval(newViewRow, newViewRow);

                if (authTestingTab != null) {
                    authTestingTab.onProfilesUpdated();
                }
                notifyStateChanged();
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        protected void exportDone(JComponent c, Transferable t, int act) {
            profileTable.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }

    // --- Collection & Endpoints Selection Actions ---

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
            List<ImportedCollection_littlespidy> allCols = importTabRef.getAllCollections();
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

    // --- Attack Execution Actions ---

    private void onAttackAll() {
        if (importTabRef != null && importTabRef.getSelectedCollection() != null) {
            CollectionComboItem currentSel = (CollectionComboItem) collectionSelectorCombo.getSelectedItem();
            if (currentSel == null || currentSel.collection == null) {
                selectCollection(importTabRef.getSelectedCollection());
            }
        }
        endpointSelectionModel.selectAll(true);
        launchAttackForItems(endpointSelectionModel.getItems());
    }

    private void onAttackSelected() {
        List<EndpointSelectionItem> selected = endpointSelectionModel.getSelectedItems();
        if (selected.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No endpoints selected. Check the box next to endpoints you want to test.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        launchAttackForItems(selected);
    }

    private void launchAttackForItems(List<EndpointSelectionItem> items) {
        if (items.isEmpty()) return;

        List<AuthProfile_littlespidy> activeProfiles = getActiveProfiles();
        if (activeProfiles.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please select at least one authentication profile.",
                    "Configuration Required",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        int threads = (Integer) threadSpinner.getValue();
        int delay = (Integer) delaySpinner.getValue();
        String runnerName = (runnerNameField != null && !runnerNameField.getText().trim().isEmpty())
                ? runnerNameField.getText().trim()
                : ("Runner " + runnerCounter);

        // Auto-switch to Auth Analyzer tab
        if (rootTab != null) {
            rootTab.switchToAuthAnalyzer();
        }

        setExecutionUIState(true);
        if (authTestingTab != null) {
            authTestingTab.startAttackExecution(items, activeProfiles, runnerName, threads, delay);
        }
    }

    private void onCancelAttack() {
        if (authTestingTab != null) {
            authTestingTab.cancelAttack();
        }
        progressStatusLabel.setText("Cancelling test run...");
        cancelBtn.setEnabled(false);
    }

    public void setExecutionUIState(boolean running) {
        attackBtn.setEnabled(!running);
        testSelectedBtn.setEnabled(!running);
        cancelBtn.setEnabled(running);
        progressBar.setVisible(running);
    }

    public void updateProgress(int completedCount, int totalCount, String currentEndpoint) {
        progressBar.setMaximum(totalCount);
        progressBar.setValue(completedCount);
        progressStatusLabel.setText("Completed " + completedCount + " of " + totalCount + " configurations");
    }

    public void onAttackFinished(boolean cancelled, int totalCompleted) {
        setExecutionUIState(false);
        if (cancelled) {
            progressStatusLabel.setText("Test run cancelled. Total completed: " + totalCompleted);
        } else {
            progressStatusLabel.setText("Test run finished. Total completed: " + totalCompleted);
        }
        runnerCounter++;
        if (runnerNameField != null) {
            runnerNameField.setText("Runner " + runnerCounter);
        }
    }

    public void onAttackError(String errorMessage) {
        progressStatusLabel.setText("Error: " + errorMessage);
    }

    // --- Accessors & Mutators for State / Persistence ---

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
        if (authTestingTab != null) {
            authTestingTab.onProfilesUpdated();
        }
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

    public Set<String> getActiveProfileIds() {
        return activeProfileIds;
    }

    public int getRunnerCounter() {
        return runnerCounter;
    }

    public void setRunnerCounter(int counter) {
        this.runnerCounter = counter > 0 ? counter : 1;
        if (runnerNameField != null) {
            runnerNameField.setText("Runner " + this.runnerCounter);
        }
    }

    public int getThreadCount() {
        return (Integer) threadSpinner.getValue();
    }

    public int getDelayMs() {
        return (Integer) delaySpinner.getValue();
    }

    public EndpointSelectionTableModel getEndpointSelectionModel() {
        return endpointSelectionModel;
    }

    // --- Inner Models ---

    public class ProfileTableModel extends AbstractTableModel {
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
                if (authTestingTab != null) {
                    authTestingTab.onProfilesUpdated();
                }
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

    public static class CollectionComboItem {
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

    public static class EndpointSelectionItem extends EndpointSelectionItem_littlespidy {
        public EndpointSelectionItem(ImportedCollection_littlespidy collection, DiscoveredEndpoint_littlespidy endpoint, boolean selected) {
            super(collection, endpoint, selected);
        }
    }

    public static class EndpointSelectionTableModel extends AbstractTableModel {
        private final String[] columns = {"Sel", "Method", "Path", "Summary"};
        private final List<EndpointSelectionItem> items = new ArrayList<>();

        public void setItems(List<EndpointSelectionItem> list) {
            items.clear();
            if (list != null) items.addAll(list);
            fireTableDataChanged();
        }

        public List<EndpointSelectionItem> getItems() {
            return items;
        }

        public List<EndpointSelectionItem> getSelectedItems() {
            List<EndpointSelectionItem> sel = new ArrayList<>();
            for (EndpointSelectionItem it : items) {
                if (it.selected) sel.add(it);
            }
            return sel;
        }

        public void selectAll(boolean select) {
            for (EndpointSelectionItem it : items) {
                it.selected = select;
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
            if (row < 0 || row >= items.size()) return "";
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
}
