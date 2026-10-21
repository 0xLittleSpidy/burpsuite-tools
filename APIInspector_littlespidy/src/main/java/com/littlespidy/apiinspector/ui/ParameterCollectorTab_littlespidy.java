// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tab dedicated to parameter collection and extraction across API endpoints.
 * Displays all query parameters and path parameters with one-click copy options
 * for individual parameters or complete lists.
 */
public class ParameterCollectorTab_littlespidy extends JPanel {

    private final List<ImportedCollection_littlespidy> collections = new ArrayList<>();
    private final List<ParameterEntry> queryParamsList = new ArrayList<>();
    private final List<ParameterEntry> pathParamsList = new ArrayList<>();

    private JComboBox<CollectionComboItem> collectionSelector;
    private JLabel summaryLabel;
    private JLabel copyFeedbackLabel;

    private ParameterTableModel queryTableModel;
    private JTable queryTable;
    private TableRowSorter<ParameterTableModel> querySorter;
    private JTextField querySearchField;
    private JTextArea queryListTextArea;

    private ParameterTableModel pathTableModel;
    private JTable pathTable;
    private TableRowSorter<ParameterTableModel> pathSorter;
    private JTextField pathSearchField;
    private JTextArea pathListTextArea;

    private static final Pattern PATH_VARIABLE_PATTERN = Pattern.compile("\\{([a-zA-Z0-9_\\-]+)\\}|:([a-zA-Z0-9_\\-]+)");

    public ParameterCollectorTab_littlespidy() {
        super(new BorderLayout(6, 6));
        setBorder(new EmptyBorder(8, 8, 8, 8));
        initComponents();
    }

    private void initComponents() {
        // --- Top Bar: Collection Selector, Global Copy Buttons, Summary ---
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));

        JPanel topBar = new JPanel(new BorderLayout(8, 4));
        JPanel leftActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        leftActions.add(new JLabel("Collection:"));
        collectionSelector = new JComboBox<>();
        collectionSelector.setPreferredSize(new Dimension(240, 26));
        collectionSelector.addActionListener(e -> rebuildParameterLists());
        leftActions.add(collectionSelector);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> rebuildParameterLists());
        leftActions.add(refreshBtn);

        JButton copyAllQueryBtn = new JButton("Copy All Query Params");
        copyAllQueryBtn.setToolTipText("Copy full list of query parameters (one per line) to clipboard");
        copyAllQueryBtn.addActionListener(e -> copyFullList(queryParamsList, "Query Parameters"));
        leftActions.add(copyAllQueryBtn);

        JButton copyAllPathBtn = new JButton("Copy All Path Params");
        copyAllPathBtn.setToolTipText("Copy full list of path parameters (one per line) to clipboard");
        copyAllPathBtn.addActionListener(e -> copyFullList(pathParamsList, "Path Parameters"));
        leftActions.add(copyAllPathBtn);

        JButton copyAllCombinedBtn = new JButton("Copy All (Query + Path)");
        copyAllCombinedBtn.setFont(copyAllCombinedBtn.getFont().deriveFont(Font.BOLD));
        copyAllCombinedBtn.setToolTipText("Copy combined unique list of all parameters (one per line) to clipboard");
        copyAllCombinedBtn.addActionListener(e -> copyCombinedList());
        leftActions.add(copyAllCombinedBtn);

        topBar.add(leftActions, BorderLayout.WEST);

        JPanel rightStats = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 2));
        summaryLabel = new JLabel("Query Params: 0 | Path Params: 0");
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.PLAIN, 12f));
        rightStats.add(summaryLabel);
        topBar.add(rightStats, BorderLayout.EAST);

        topContainer.add(topBar);

        // Feedback notification banner
        JPanel feedbackBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        copyFeedbackLabel = new JLabel(" ");
        copyFeedbackLabel.setFont(copyFeedbackLabel.getFont().deriveFont(Font.ITALIC, 11f));
        copyFeedbackLabel.setForeground(new Color(0, 120, 40));
        feedbackBar.add(copyFeedbackLabel);
        topContainer.add(feedbackBar);

        add(topContainer, BorderLayout.NORTH);

        // --- Center: Split Pane for Query Parameters and Path Parameters ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);

        // Left: Query Parameters Section
        JPanel querySection = createQuerySection();
        splitPane.setLeftComponent(querySection);

        // Right: Path Parameters Section
        JPanel pathSection = createPathSection();
        splitPane.setRightComponent(pathSection);

        add(splitPane, BorderLayout.CENTER);
    }

    private JPanel createQuerySection() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new TitledBorder("Query Parameters"));

        JPanel headerBar = new JPanel(new BorderLayout(6, 2));
        JPanel searchBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        searchBox.add(new JLabel("Filter:"));
        querySearchField = new JTextField(14);
        querySearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { filterQueryTable(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { filterQueryTable(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { filterQueryTable(); }
        });
        searchBox.add(querySearchField);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> querySearchField.setText(""));
        searchBox.add(clearBtn);
        headerBar.add(searchBox, BorderLayout.WEST);

        JButton copyListBtn = new JButton("Copy Query List");
        copyListBtn.addActionListener(e -> copyFullList(queryParamsList, "Query Parameters"));
        headerBar.add(copyListBtn, BorderLayout.EAST);
        panel.add(headerBar, BorderLayout.NORTH);

        // Query Parameters Table
        queryTableModel = new ParameterTableModel(queryParamsList);
        queryTable = new JTable(queryTableModel);
        querySorter = new TableRowSorter<>(queryTableModel);
        queryTable.setRowSorter(querySorter);
        queryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        queryTable.getColumnModel().getColumn(3).setMaxWidth(70);

        // Click on row to copy individual parameter
        queryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = queryTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = queryTable.convertRowIndexToModel(row);
                    ParameterEntry entry = queryTableModel.getEntry(modelRow);
                    if (entry != null) {
                        copySingleParameter(entry.name);
                    }
                }
            }
        });

        // Tabbed view: Table view vs Plain list view
        JTabbedPane queryTabs = new JTabbedPane();
        queryTabs.addTab("Parameter Table (Click to Copy)", new JScrollPane(queryTable));

        queryListTextArea = new JTextArea();
        queryListTextArea.setEditable(false);
        queryListTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel plainListPanel = new JPanel(new BorderLayout(4, 4));
        plainListPanel.add(new JScrollPane(queryListTextArea), BorderLayout.CENTER);
        JButton copyPlainBtn = new JButton("Copy All Lines to Clipboard");
        copyPlainBtn.addActionListener(e -> copyFullList(queryParamsList, "Query Parameters"));
        plainListPanel.add(copyPlainBtn, BorderLayout.SOUTH);
        queryTabs.addTab("Plain List (One Per Line)", plainListPanel);

        panel.add(queryTabs, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createPathSection() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(new TitledBorder("Path Parameters"));

        JPanel headerBar = new JPanel(new BorderLayout(6, 2));
        JPanel searchBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        searchBox.add(new JLabel("Filter:"));
        pathSearchField = new JTextField(14);
        pathSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { filterPathTable(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { filterPathTable(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { filterPathTable(); }
        });
        searchBox.add(pathSearchField);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> pathSearchField.setText(""));
        searchBox.add(clearBtn);
        headerBar.add(searchBox, BorderLayout.WEST);

        JButton copyListBtn = new JButton("Copy Path List");
        copyListBtn.addActionListener(e -> copyFullList(pathParamsList, "Path Parameters"));
        headerBar.add(copyListBtn, BorderLayout.EAST);
        panel.add(headerBar, BorderLayout.NORTH);

        // Path Parameters Table
        pathTableModel = new ParameterTableModel(pathParamsList);
        pathTable = new JTable(pathTableModel);
        pathSorter = new TableRowSorter<>(pathTableModel);
        pathTable.setRowSorter(pathSorter);
        pathTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        pathTable.getColumnModel().getColumn(3).setMaxWidth(70);

        // Click on row to copy individual parameter
        pathTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = pathTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = pathTable.convertRowIndexToModel(row);
                    ParameterEntry entry = pathTableModel.getEntry(modelRow);
                    if (entry != null) {
                        copySingleParameter(entry.name);
                    }
                }
            }
        });

        // Tabbed view: Table view vs Plain list view
        JTabbedPane pathTabs = new JTabbedPane();
        pathTabs.addTab("Parameter Table (Click to Copy)", new JScrollPane(pathTable));

        pathListTextArea = new JTextArea();
        pathListTextArea.setEditable(false);
        pathListTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel plainListPanel = new JPanel(new BorderLayout(4, 4));
        plainListPanel.add(new JScrollPane(pathListTextArea), BorderLayout.CENTER);
        JButton copyPlainBtn = new JButton("Copy All Lines to Clipboard");
        copyPlainBtn.addActionListener(e -> copyFullList(pathParamsList, "Path Parameters"));
        plainListPanel.add(copyPlainBtn, BorderLayout.SOUTH);
        pathTabs.addTab("Plain List (One Per Line)", plainListPanel);

        panel.add(pathTabs, BorderLayout.CENTER);
        return panel;
    }

    public synchronized void updateCollections(List<ImportedCollection_littlespidy> cols) {
        collections.clear();
        if (cols != null) {
            collections.addAll(cols);
        }

        // Rebuild combobox
        collectionSelector.removeAllItems();
        collectionSelector.addItem(new CollectionComboItem(null, "[All Imported Collections]"));
        for (ImportedCollection_littlespidy c : collections) {
            collectionSelector.addItem(new CollectionComboItem(c, c.getName() + " (" + c.getEndpointCount() + ")"));
        }

        rebuildParameterLists();
    }

    public synchronized void rebuildParameterLists() {
        queryParamsList.clear();
        pathParamsList.clear();

        CollectionComboItem sel = (CollectionComboItem) collectionSelector.getSelectedItem();
        List<ImportedCollection_littlespidy> targetCols = new ArrayList<>();
        if (sel == null || sel.collection == null) {
            targetCols.addAll(collections);
        } else {
            targetCols.add(sel.collection);
        }

        Map<String, ParameterEntry> queryMap = new LinkedHashMap<>();
        Map<String, ParameterEntry> pathMap = new LinkedHashMap<>();

        for (ImportedCollection_littlespidy col : targetCols) {
            for (DiscoveredEndpoint_littlespidy ep : col.getEndpoints()) {
                String epDesc = ep.getMethod() + " " + ep.getPath();

                // 1. Query parameters
                if (ep.getQueryParams() != null) {
                    for (Map.Entry<String, String> qEntry : ep.getQueryParams().entrySet()) {
                        String name = qEntry.getKey();
                        if (name == null || name.isBlank()) continue;
                        name = name.trim();
                        String val = qEntry.getValue() != null ? qEntry.getValue() : "";

                        ParameterEntry p = queryMap.computeIfAbsent(name, ParameterEntry::new);
                        p.addEndpoint(epDesc);
                        if (p.sampleValue.isEmpty() && !val.isEmpty()) {
                            p.sampleValue = val;
                        }
                    }
                }

                // 2. Path parameters from explicit map
                if (ep.getPathParams() != null) {
                    for (Map.Entry<String, String> pEntry : ep.getPathParams().entrySet()) {
                        String name = pEntry.getKey();
                        if (name == null || name.isBlank()) continue;
                        name = name.trim();
                        String val = pEntry.getValue() != null ? pEntry.getValue() : "";

                        ParameterEntry p = pathMap.computeIfAbsent(name, ParameterEntry::new);
                        p.addEndpoint(epDesc);
                        if (p.sampleValue.isEmpty() && !val.isEmpty()) {
                            p.sampleValue = val;
                        }
                    }
                }

                // 3. Extract path parameters from template variables in path (e.g. /users/{id} or /items/:code)
                if (ep.getPath() != null) {
                    Matcher m = PATH_VARIABLE_PATTERN.matcher(ep.getPath());
                    while (m.find()) {
                        String name = m.group(1) != null ? m.group(1) : m.group(2);
                        if (name != null && !name.isBlank()) {
                            name = name.trim();
                            ParameterEntry p = pathMap.computeIfAbsent(name, ParameterEntry::new);
                            p.addEndpoint(epDesc);
                        }
                    }
                }
            }
        }

        queryParamsList.addAll(queryMap.values());
        pathParamsList.addAll(pathMap.values());

        queryTableModel.fireTableDataChanged();
        pathTableModel.fireTableDataChanged();

        // Update plain text areas (each parameter on a separate line)
        StringBuilder querySb = new StringBuilder();
        for (ParameterEntry p : queryParamsList) {
            querySb.append(p.name).append("\n");
        }
        queryListTextArea.setText(querySb.toString());
        queryListTextArea.setCaretPosition(0);

        StringBuilder pathSb = new StringBuilder();
        for (ParameterEntry p : pathParamsList) {
            pathSb.append(p.name).append("\n");
        }
        pathListTextArea.setText(pathSb.toString());
        pathListTextArea.setCaretPosition(0);

        summaryLabel.setText("Query Params: " + queryParamsList.size() + " | Path Params: " + pathParamsList.size());
    }

    private void filterQueryTable() {
        String q = querySearchField.getText().trim();
        if (q.isEmpty()) {
            querySorter.setRowFilter(null);
        } else {
            querySorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
        }
    }

    private void filterPathTable() {
        String q = pathSearchField.getText().trim();
        if (q.isEmpty()) {
            pathSorter.setRowFilter(null);
        } else {
            pathSorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
        }
    }

    private void copySingleParameter(String name) {
        if (name == null || name.isBlank()) return;
        copyToClipboard(name);
        showFeedback("Copied parameter '" + name + "' to clipboard.");
    }

    private void copyFullList(List<ParameterEntry> list, String label) {
        if (list == null || list.isEmpty()) {
            showFeedback("No " + label + " to copy.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (ParameterEntry p : list) {
            sb.append(p.name).append("\n");
        }
        copyToClipboard(sb.toString().trim());
        showFeedback("Copied " + list.size() + " " + label + " (one per line) to clipboard.");
    }

    private void copyCombinedList() {
        Set<String> unique = new LinkedHashSet<>();
        for (ParameterEntry p : queryParamsList) {
            unique.add(p.name);
        }
        for (ParameterEntry p : pathParamsList) {
            unique.add(p.name);
        }

        if (unique.isEmpty()) {
            showFeedback("No parameters found to copy.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (String s : unique) {
            sb.append(s).append("\n");
        }
        copyToClipboard(sb.toString().trim());
        showFeedback("Copied " + unique.size() + " combined parameters (one per line) to clipboard.");
    }

    private void copyToClipboard(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (Exception ex) {
            // Ignore clipboard errors
        }
    }

    private void showFeedback(String message) {
        copyFeedbackLabel.setText(message);
        javax.swing.Timer timer = new javax.swing.Timer(4000, e -> copyFeedbackLabel.setText(" "));
        timer.setRepeats(false);
        timer.start();
    }

    // --- Data structures & Table model ---

    public static class ParameterEntry {
        public final String name;
        public String sampleValue = "";
        public final Set<String> endpoints = new LinkedHashSet<>();

        public ParameterEntry(String name) {
            this.name = name;
        }

        public void addEndpoint(String ep) {
            if (ep != null) endpoints.add(ep);
        }
    }

    private static class ParameterTableModel extends AbstractTableModel {
        private final String[] columns = {"Parameter Name", "Sample Value", "Endpoints Used", "Action"};
        private final List<ParameterEntry> entries;

        public ParameterTableModel(List<ParameterEntry> entries) {
            this.entries = entries;
        }

        public ParameterEntry getEntry(int row) {
            if (row >= 0 && row < entries.size()) {
                return entries.get(row);
            }
            return null;
        }

        @Override public int getRowCount() { return entries.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            ParameterEntry p = entries.get(row);
            switch (col) {
                case 0: return p.name;
                case 1: return p.sampleValue.isEmpty() ? "-" : p.sampleValue;
                case 2: return p.endpoints.size() + " endpoint(s)";
                case 3: return "Copy";
                default: return "";
            }
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
}
