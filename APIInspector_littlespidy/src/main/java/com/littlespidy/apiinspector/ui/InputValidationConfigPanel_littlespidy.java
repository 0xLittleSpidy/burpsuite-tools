// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationPayloadItem_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTechnique_littlespidy;
import com.littlespidy.apiinspector.model.NaughtyStringsParser_littlespidy;
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
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Configuration sub-panel for Input Validation fuzzing.
 * Displays all individual attack payloads (OWASP and BLNS) as distinct table rows
 * without aggregating them into count buckets.
 * Features a three-tier layout:
 * Tier 1: Individual Payloads table with filtering, search, and row attack buttons.
 * Tier 2: Endpoints to Test panel with API Collection selector, filter, and endpoints checklist.
 * Tier 3: Execution controls, thread/delay spinners, and batch Attack buttons.
 */
public class InputValidationConfigPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private InputValidationTab_littlespidy inputValidationTab;
    private APIInspectorTab_littlespidy rootTab;
    private APIImportTab_littlespidy importTabRef;

    // Payloads UI
    private final List<InputValidationPayloadItem_littlespidy> allPayloads = new ArrayList<>();
    private final List<InputValidationPayloadItem_littlespidy> displayedPayloads = new ArrayList<>();
    private final PayloadTableModel payloadTableModel = new PayloadTableModel();
    private final JTable payloadTable = new JTable(payloadTableModel);

    private final JComboBox<String> categoryFilterCombo = new JComboBox<>(new String[]{
            "All Payloads",
            "Standard OWASP",
            "Naughty Strings (BLNS)",
            "BLNS: Reserved Identifiers",
            "BLNS: Numeric Boundaries",
            "BLNS: Special Characters",
            "BLNS: Unicode & Encoding",
            "BLNS: Script Injection",
            "BLNS: SQL & Code Injection",
            "BLNS: Unwanted Interpolation",
            "BLNS: File Inclusion & Traversal",
            "BLNS: MSDOS / Windows Filenames",
            "BLNS: Terminal & Prompt Injection",
            "Custom Wordlists"
    });
    private final JTextField payloadSearchField = new JTextField(14);
    private final JLabel payloadCountLabel = new JLabel("0 payloads");

    // Endpoints Selection UI
    private JComboBox<CollectionComboItem> collectionSelectorCombo;
    private final EndpointSelectionTableModel_littlespidy endpointSelectionModel = new EndpointSelectionTableModel_littlespidy();
    private final JTable endpointSelectionTable = new JTable(endpointSelectionModel);
    private final JTextField endpointFilterField = new JTextField(14);

    // Execution Controls UI
    private final JTextField targetEndpointField = new JTextField("https://example.com/api/v1/search?query=test", 24);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 30, 1));
    private final JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(50, 0, 10000, 10));
    private final JTextField runnerNameField = new JTextField("Input Validation Runner 1", 14);
    private final JButton attackSelectedBtn = new JButton("Attack Selected Endpoints (Batch Fuzz)");
    private final JButton attackAllEndpointsBtn = new JButton("Attack All Endpoints");

    private int runnerCount = 1;

    public InputValidationConfigPanel_littlespidy(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        this.api = api;

        // Load all individual payloads (OWASP + BLNS individual strings)
        this.allPayloads.addAll(NaughtyStringsParser_littlespidy.loadAllIndividualPayloads());
        this.displayedPayloads.addAll(this.allPayloads);

        setBorder(new EmptyBorder(6, 6, 6, 6));
        initComponents();
        updatePayloadCountLabel();
    }

    public void setInputValidationTab(InputValidationTab_littlespidy inputValidationTab) {
        this.inputValidationTab = inputValidationTab;
    }

    public void setRootTab(APIInspectorTab_littlespidy rootTab) {
        this.rootTab = rootTab;
    }

    public void setImportTabRef(APIImportTab_littlespidy importTabRef) {
        this.importTabRef = importTabRef;
        refreshCollectionsCombo();
    }

    public String getTargetEndpoint() {
        return targetEndpointField.getText().trim();
    }

    public void setTargetEndpoint(String url) {
        if (url != null && !url.isBlank()) {
            targetEndpointField.setText(url.trim());
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

    public List<InputValidationPayloadItem_littlespidy> getPayloadItems() {
        return new ArrayList<>(allPayloads);
    }

    public void setPayloadItems(List<InputValidationPayloadItem_littlespidy> newItems) {
        allPayloads.clear();
        if (newItems != null) {
            allPayloads.addAll(newItems);
        } else {
            allPayloads.addAll(NaughtyStringsParser_littlespidy.loadAllIndividualPayloads());
        }
        applyFilter();
    }

    /**
     * Preserved for backward-compatibility with tests and legacy callers.
     */
    public List<InputValidationTechnique_littlespidy> getTechniques() {
        return InputValidationTechnique_littlespidy.getDefaultTechniques();
    }

    public void setTechniques(List<InputValidationTechnique_littlespidy> techniques) {
        // Reload payloads representation
        applyFilter();
    }

    private void initComponents() {
        JPanel centerContainer = new JPanel(new BorderLayout(4, 4));

        // 1. Tier 1 (Top): Individual Payloads Panel
        JPanel payloadsPanel = new JPanel(new BorderLayout(4, 4));
        payloadsPanel.setBorder(new TitledBorder("Input Validation Individual Attack Payloads"));

        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        filterBar.add(new JLabel("Category:"));
        categoryFilterCombo.addActionListener(e -> applyFilter());
        filterBar.add(categoryFilterCombo);

        filterBar.add(new JLabel("Search:"));
        payloadSearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        filterBar.add(payloadSearchField);

        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> {
            for (InputValidationPayloadItem_littlespidy p : displayedPayloads) {
                p.setEnabled(true);
            }
            payloadTableModel.fireTableDataChanged();
            updatePayloadCountLabel();
        });
        filterBar.add(selectAllBtn);

        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> {
            for (InputValidationPayloadItem_littlespidy p : displayedPayloads) {
                p.setEnabled(false);
            }
            payloadTableModel.fireTableDataChanged();
            updatePayloadCountLabel();
        });
        filterBar.add(deselectAllBtn);

        JButton loadCustomBtn = new JButton("Load Custom Wordlist...");
        loadCustomBtn.addActionListener(e -> loadCustomWordlist());
        filterBar.add(loadCustomBtn);

        filterBar.add(payloadCountLabel);
        payloadsPanel.add(filterBar, BorderLayout.NORTH);

        payloadTable.setFillsViewportHeight(true);
        payloadTable.setRowHeight(24);
        payloadTable.getColumnModel().getColumn(0).setMaxWidth(55);
        payloadTable.getColumnModel().getColumn(1).setMaxWidth(90);
        payloadTable.getColumnModel().getColumn(2).setPreferredWidth(170);
        payloadTable.getColumnModel().getColumn(3).setPreferredWidth(260);
        payloadTable.getColumnModel().getColumn(4).setPreferredWidth(200);
        payloadTable.getColumnModel().getColumn(5).setMaxWidth(90);

        payloadTable.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());
        payloadTable.getColumnModel().getColumn(5).setCellEditor(new ButtonEditor(new JCheckBox(), this::launchSinglePayloadAttack));
        payloadsPanel.add(new JScrollPane(payloadTable), BorderLayout.CENTER);

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

        // 3. Tier 3 (Bottom): Execution Controls Panel
        JPanel execControlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        execControlsPanel.setBorder(new TitledBorder("Execution Controls"));

        execControlsPanel.add(new JLabel("Target (Fallback):"));
        execControlsPanel.add(targetEndpointField);

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

    private void applyFilter() {
        String selectedCategory = (String) categoryFilterCombo.getSelectedItem();
        String search = payloadSearchField.getText().trim().toLowerCase(Locale.ROOT);
        displayedPayloads.clear();

        for (InputValidationPayloadItem_littlespidy item : allPayloads) {
            // Category check
            boolean categoryMatch = true;
            if ("Standard OWASP".equals(selectedCategory)) {
                categoryMatch = !item.isBlns() && !item.isCustom();
            } else if ("Naughty Strings (BLNS)".equals(selectedCategory)) {
                categoryMatch = item.isBlns();
            } else if ("Custom Wordlists".equals(selectedCategory)) {
                categoryMatch = item.isCustom();
            } else if (selectedCategory != null && !"All Payloads".equals(selectedCategory)) {
                categoryMatch = item.getCategory().toLowerCase(Locale.ROOT).contains(selectedCategory.toLowerCase(Locale.ROOT));
            }

            if (!categoryMatch) {
                continue;
            }

            // Search query check
            if (!search.isEmpty()) {
                String id = item.getId().toLowerCase(Locale.ROOT);
                String cat = item.getCategory().toLowerCase(Locale.ROOT);
                String val = item.getPayload().toLowerCase(Locale.ROOT);
                String desc = item.getDescription().toLowerCase(Locale.ROOT);

                if (!id.contains(search) && !cat.contains(search) && !val.contains(search) && !desc.contains(search)) {
                    continue;
                }
            }

            displayedPayloads.add(item);
        }

        payloadTableModel.fireTableDataChanged();
        updatePayloadCountLabel();
    }

    private void updatePayloadCountLabel() {
        long enabledCount = allPayloads.stream().filter(InputValidationPayloadItem_littlespidy::isEnabled).count();
        payloadCountLabel.setText("Showing " + displayedPayloads.size() + " / " + allPayloads.size() + " payloads (" + enabledCount + " enabled)");
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

    private void loadCustomWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Wordlist File (.txt)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            try {
                List<InputValidationPayloadItem_littlespidy> customItems = NaughtyStringsParser_littlespidy.parseCustomFileToPayloads(f);
                allPayloads.addAll(customItems);
                applyFilter();
                JOptionPane.showMessageDialog(this,
                        "Successfully loaded wordlist: " + f.getName() + " (" + customItems.size() + " payloads).",
                        "Wordlist Loaded",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to load wordlist: " + ex.getMessage(),
                        "Load Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private HttpRequest buildTargetRequest() {
        String targetUrl = targetEndpointField.getText().trim();
        if (targetUrl.isEmpty()) {
            targetUrl = "https://example.com/api/v1/search?query=test";
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
        if (inputValidationTab == null || rootTab == null) return;

        List<EndpointSelectionItem_littlespidy> selectedEndpoints = endpointSelectionModel.getSelectedItems();
        List<InputValidationPayloadItem_littlespidy> activePayloads = new ArrayList<>();
        for (InputValidationPayloadItem_littlespidy p : allPayloads) {
            if (p.isEnabled()) {
                activePayloads.add(p);
            }
        }

        if (activePayloads.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No payloads enabled. Check at least one payload to run attacks.", "Configuration Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String runnerName = runnerNameField.getText().trim();
        if (runnerName.isEmpty()) {
            runnerName = "Input Validation Runner " + (++runnerCount);
        }

        // Switch to Input Validation tab
        rootTab.selectTab(inputValidationTab);

        if (!selectedEndpoints.isEmpty()) {
            inputValidationTab.executeAttack(
                    selectedEndpoints,
                    getTargetEndpoint(),
                    activePayloads,
                    getThreadCount(),
                    getDelayMs(),
                    runnerName
            );
        } else {
            HttpRequest targetReq = buildTargetRequest();
            inputValidationTab.executeAttackForPayloads(
                    targetReq,
                    activePayloads,
                    getThreadCount(),
                    getDelayMs(),
                    runnerName
            );
        }

        runnerNameField.setText("Input Validation Runner " + (++runnerCount));
    }

    private void launchSinglePayloadAttack(int rowIndex) {
        if (inputValidationTab == null || rootTab == null || rowIndex < 0 || rowIndex >= displayedPayloads.size()) return;

        InputValidationPayloadItem_littlespidy payloadItem = displayedPayloads.get(rowIndex);
        List<EndpointSelectionItem_littlespidy> selectedEndpoints = endpointSelectionModel.getSelectedItems();
        String runnerName = "Fuzz - " + payloadItem.getId();

        // Switch to Input Validation tab
        rootTab.selectTab(inputValidationTab);

        if (!selectedEndpoints.isEmpty()) {
            inputValidationTab.executeAttack(
                    selectedEndpoints,
                    getTargetEndpoint(),
                    Collections.singletonList(payloadItem),
                    1,
                    getDelayMs(),
                    runnerName
            );
        } else {
            HttpRequest targetReq = buildTargetRequest();
            inputValidationTab.executeAttackForPayloads(
                    targetReq,
                    Collections.singletonList(payloadItem),
                    1,
                    getDelayMs(),
                    runnerName
            );
        }
    }

    private class PayloadTableModel extends AbstractTableModel {
        private final String[] columns = {"Enable", "ID", "Category", "Payload Value", "Detection Signatures", "Action"};

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
            return columnIndex == 0 || columnIndex == 5;
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
                case 4: return item.getDetectionSignaturesSummary();
                case 5: return "Attack";
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
