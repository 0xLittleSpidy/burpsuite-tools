// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.model.AuthProfileComboItem_littlespidy;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.CorsTechnique_littlespidy;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.littlespidy.apiinspector.ui.AuthAnalyzerConfigTab_littlespidy.CollectionComboItem;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration sub-panel for CORS testing.
 * Features a three-tier layout:
 * Tier 1: PortSwigger 29 CORS bypass techniques table with individual attack buttons.
 * Tier 2: Endpoints to Test panel with API Collection selector, filter, and endpoints checklist.
 * Tier 3: Execution controls, thread/delay spinners, and batch Attack buttons.
 */
public class CorsConfigPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private CorsTab_littlespidy corsTab;
    private APIInspectorTab_littlespidy rootTab;
    private APIImportTab_littlespidy importTabRef;

    // Techniques Table UI
    private final List<CorsTechnique_littlespidy> techniques = new ArrayList<>();
    private final CorsTechniquesTableModel tableModel = new CorsTechniquesTableModel();
    private final JTable techniquesTable = new JTable(tableModel);

    // Endpoints Selection UI
    private JComboBox<CollectionComboItem> collectionSelectorCombo;
    private final EndpointSelectionTableModel_littlespidy endpointSelectionModel = new EndpointSelectionTableModel_littlespidy();
    private final JTable endpointSelectionTable = new JTable(endpointSelectionModel);
    private final JTextField endpointFilterField = new JTextField(16);

    // Execution Controls UI
    private final JComboBox<AuthProfileComboItem_littlespidy> authProfileCombo = new JComboBox<>();
    private final JTextField sessionHeaderField = new JTextField(22);
    private final JTextField targetUrlField = new JTextField("https://example.com", 20);
    private final JTextField attackerDomainField = new JTextField("evil.com", 12);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 30, 1));
    private final JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 10000, 10));
    private final JTextField runnerNameField = new JTextField("CORS Runner 1", 12);
    private final JButton attackSelectedBtn = new JButton("Attack Selected Endpoints (Batch CORS)");
    private final JButton attackAllEndpointsBtn = new JButton("Attack All Endpoints");

    private int runnerCount = 1;

    public CorsConfigPanel_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.techniques.addAll(CorsTechnique_littlespidy.getDefaultTechniques());

        setBorder(new EmptyBorder(6, 6, 6, 6));
        initComponents();
    }

    public void setCorsTab(CorsTab_littlespidy corsTab) {
        this.corsTab = corsTab;
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

    public String getTargetUrl() {
        return targetUrlField.getText().trim();
    }

    public void setTargetUrl(String url) {
        if (url != null && !url.isBlank()) {
            targetUrlField.setText(url.trim());
            tableModel.fireTableDataChanged();
        }
    }

    public String getAttackerDomain() {
        return attackerDomainField.getText().trim();
    }

    public void setAttackerDomain(String domain) {
        if (domain != null && !domain.isBlank()) {
            attackerDomainField.setText(domain.trim());
            tableModel.fireTableDataChanged();
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

    public List<CorsTechnique_littlespidy> getTechniques() {
        return new ArrayList<>(techniques);
    }

    public void setTechniques(List<CorsTechnique_littlespidy> newTechniques) {
        techniques.clear();
        if (newTechniques != null) {
            techniques.addAll(newTechniques);
        } else {
            techniques.addAll(CorsTechnique_littlespidy.getDefaultTechniques());
        }
        tableModel.fireTableDataChanged();
    }

    private void initComponents() {
        JPanel centerContainer = new JPanel(new BorderLayout(4, 4));

        // 1. Tier 1 (Top): CORS Bypass Techniques Panel
        JPanel techniquesPanel = new JPanel(new BorderLayout(4, 4));
        techniquesPanel.setBorder(new TitledBorder("CORS Bypass Techniques (PortSwigger)"));

        JPanel techToolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton selectAllTechBtn = new JButton("Select All");
        selectAllTechBtn.addActionListener(e -> {
            for (CorsTechnique_littlespidy t : techniques) {
                t.setEnabled(true);
            }
            tableModel.fireTableDataChanged();
        });
        JButton deselectAllTechBtn = new JButton("Deselect All");
        deselectAllTechBtn.addActionListener(e -> {
            for (CorsTechnique_littlespidy t : techniques) {
                t.setEnabled(false);
            }
            tableModel.fireTableDataChanged();
        });
        techToolBar.add(selectAllTechBtn);
        techToolBar.add(deselectAllTechBtn);
        techToolBar.add(new JLabel("Target:"));
        techToolBar.add(targetUrlField);
        targetUrlField.addActionListener(e -> tableModel.fireTableDataChanged());
        techToolBar.add(new JLabel("Attacker Domain:"));
        techToolBar.add(attackerDomainField);
        attackerDomainField.addActionListener(e -> tableModel.fireTableDataChanged());
        techniquesPanel.add(techToolBar, BorderLayout.NORTH);

        techniquesTable.setFillsViewportHeight(true);
        techniquesTable.setRowHeight(24);
        techniquesTable.getColumnModel().getColumn(0).setMaxWidth(60);
        techniquesTable.getColumnModel().getColumn(1).setMaxWidth(70);
        techniquesTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        techniquesTable.getColumnModel().getColumn(3).setPreferredWidth(260);
        techniquesTable.getColumnModel().getColumn(4).setPreferredWidth(300);
        techniquesTable.getColumnModel().getColumn(5).setMaxWidth(100);

        techniquesTable.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());
        techniquesTable.getColumnModel().getColumn(5).setCellEditor(new ButtonEditor(new JCheckBox(), this::launchSingleTechniqueAttack));
        techniquesPanel.add(new JScrollPane(techniquesTable), BorderLayout.CENTER);

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

        // Split Techniques (top) and Endpoints (middle)
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, techniquesPanel, endpointsPanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);
        centerContainer.add(splitPane, BorderLayout.CENTER);

        add(centerContainer, BorderLayout.CENTER);

        // 3. Tier 3 (Bottom): Execution Controls Panel
        JPanel execControlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        execControlsPanel.setBorder(new TitledBorder("Execution Controls"));

        execControlsPanel.add(new JLabel("Auth Profile / Session:"));
        authProfileCombo.setPreferredSize(new Dimension(220, 24));
        authProfileCombo.addItem(new AuthProfileComboItem_littlespidy(null, "[No Auth / Unauthenticated]"));
        authProfileCombo.addActionListener(e -> onAuthProfileSelectionChanged());
        execControlsPanel.add(authProfileCombo);

        execControlsPanel.add(new JLabel("Auth Header:"));
        sessionHeaderField.setToolTipText("Enter raw auth header (e.g. Authorization: Bearer <token>)");
        execControlsPanel.add(sessionHeaderField);

        execControlsPanel.add(new JLabel("Threads:"));
        execControlsPanel.add(threadSpinner);

        execControlsPanel.add(new JLabel("Delay (ms):"));
        execControlsPanel.add(delaySpinner);

        execControlsPanel.add(new JLabel("Runner Name:"));
        execControlsPanel.add(runnerNameField);

        attackSelectedBtn.setFont(attackSelectedBtn.getFont().deriveFont(Font.BOLD));
        attackSelectedBtn.addActionListener(e -> launchAttackForSelectedEndpoints());
        execControlsPanel.add(attackSelectedBtn);

        attackAllEndpointsBtn.addActionListener(e -> {
            endpointSelectionModel.selectAll(true);
            launchAttackForSelectedEndpoints();
        });
        execControlsPanel.add(attackAllEndpointsBtn);

        add(execControlsPanel, BorderLayout.SOUTH);
    }

    public void refreshCollectionsCombo() {
        if (collectionSelectorCombo == null) return;
        collectionSelectorCombo.removeAllItems();
        if (importTabRef != null) {
            List<ImportedCollection_littlespidy> allCols = importTabRef.getAllCollections();
            collectionSelectorCombo.addItem(new CollectionComboItem(null, "[All Imported Collections]"));
            for (ImportedCollection_littlespidy c : allCols) {
                collectionSelectorCombo.addItem(new CollectionComboItem(c, c.getName() + " (" + c.getEndpointCount() + ")"));
            }
        } else {
            collectionSelectorCombo.addItem(new CollectionComboItem(null, "[No Collections Loaded]"));
        }
        onCollectionSelectionChanged();
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

    private HttpRequest buildTargetRequest() {
        String targetUrl = targetUrlField.getText().trim();
        if (targetUrl.isEmpty()) {
            targetUrl = "https://example.com";
        }
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
        }

        HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl);
        if (request == null) {
            HttpService service = HttpService.httpService("localhost", 443, true);
            request = HttpRequest.httpRequest(service, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        }
        return request;
    }

    private void launchAttackForSelectedEndpoints() {
        if (corsTab == null || rootTab == null) return;

        List<EndpointSelectionItem_littlespidy> selectedEndpoints = endpointSelectionModel.getSelectedItems();
        String runnerName = runnerNameField.getText().trim();
        if (runnerName.isEmpty()) {
            runnerName = "CORS Runner " + (++runnerCount);
        }

        AuthProfileComboItem_littlespidy authSel = (AuthProfileComboItem_littlespidy) authProfileCombo.getSelectedItem();
        AuthProfile_littlespidy profile = authSel != null ? authSel.profile : null;
        String customAuthHeader = sessionHeaderField.getText().trim();

        // Switch to CORS tab
        rootTab.selectTab(corsTab);

        if (!selectedEndpoints.isEmpty()) {
            corsTab.executeAttack(
                    selectedEndpoints,
                    getTargetUrl(),
                    getAttackerDomain(),
                    profile,
                    customAuthHeader,
                    techniques,
                    getThreadCount(),
                    getDelayMs(),
                    runnerName
            );
        } else {
            // Fallback to single target URL
            HttpRequest targetReq = buildTargetRequest();
            corsTab.executeAttack(
                    targetReq,
                    getTargetUrl(),
                    getAttackerDomain(),
                    profile,
                    customAuthHeader,
                    techniques,
                    getThreadCount(),
                    getDelayMs(),
                    runnerName
            );
        }

        runnerNameField.setText("CORS Runner " + (++runnerCount));
    }

    private void launchSingleTechniqueAttack(int rowIndex) {
        if (corsTab == null || rootTab == null || rowIndex < 0 || rowIndex >= techniques.size()) return;

        CorsTechnique_littlespidy tech = techniques.get(rowIndex);
        List<EndpointSelectionItem_littlespidy> selectedEndpoints = endpointSelectionModel.getSelectedItems();
        String runnerName = "CORS - " + tech.getName();

        AuthProfileComboItem_littlespidy authSel = (AuthProfileComboItem_littlespidy) authProfileCombo.getSelectedItem();
        AuthProfile_littlespidy profile = authSel != null ? authSel.profile : null;
        String customAuthHeader = sessionHeaderField.getText().trim();

        // Switch to CORS tab
        rootTab.selectTab(corsTab);

        if (!selectedEndpoints.isEmpty()) {
            corsTab.executeAttack(
                    selectedEndpoints,
                    getTargetUrl(),
                    getAttackerDomain(),
                    profile,
                    customAuthHeader,
                    Collections.singletonList(tech),
                    1,
                    getDelayMs(),
                    runnerName
            );
        } else {
            HttpRequest targetReq = buildTargetRequest();
            corsTab.executeAttack(
                    targetReq,
                    getTargetUrl(),
                    getAttackerDomain(),
                    profile,
                    customAuthHeader,
                    Collections.singletonList(tech),
                    1,
                    getDelayMs(),
                    runnerName
            );
        }
    }

    private class CorsTechniquesTableModel extends AbstractTableModel {
        private final String[] columns = {"Enable", "ID", "Technique Name", "Origin Injected", "Description / Bypass Specifics", "Action"};

        @Override
        public int getRowCount() {
            return techniques.size();
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
            return columnIndex == 0 || columnIndex == 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= techniques.size()) return "";
            CorsTechnique_littlespidy t = techniques.get(rowIndex);
            switch (columnIndex) {
                case 0: return t.isEnabled();
                case 1: return t.getId();
                case 2: return t.getName();
                case 3: return t.resolveOrigin(getTargetUrl(), getAttackerDomain());
                case 4: return t.getDescription() + " (" + t.getBrowserNote() + ")";
                case 5: return "Attack";
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= techniques.size()) return;
            CorsTechnique_littlespidy t = techniques.get(rowIndex);
            if (columnIndex == 0 && aValue instanceof Boolean) {
                t.setEnabled((Boolean) aValue);
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }

    private static class ButtonRenderer extends JButton implements TableCellRenderer {
        public ButtonRenderer() {
            setOpaque(true);
            setMargin(new Insets(1, 4, 1, 4));
            setFont(getFont().deriveFont(Font.PLAIN, 11f));
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            setText(value != null ? value.toString() : "Attack");
            return this;
        }
    }

    private static class ButtonEditor extends DefaultCellEditor {
        private final JButton button;
        private final java.util.function.Consumer<Integer> action;
        private int currentRow;

        public ButtonEditor(JCheckBox checkBox, java.util.function.Consumer<Integer> action) {
            super(checkBox);
            this.action = action;
            this.button = new JButton();
            this.button.setOpaque(true);
            this.button.setMargin(new Insets(1, 4, 1, 4));
            this.button.setFont(this.button.getFont().deriveFont(Font.PLAIN, 11f));
            this.button.addActionListener(e -> {
                fireEditingStopped();
                if (action != null) {
                    action.accept(currentRow);
                }
            });
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value,
                                                     boolean isSelected, int row, int column) {
            this.currentRow = row;
            button.setText(value != null ? value.toString() : "Attack");
            return button;
        }

        @Override
        public Object getCellEditorValue() {
            return "Attack";
        }
    }
}
