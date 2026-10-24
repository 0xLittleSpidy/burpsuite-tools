// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import com.littlespidy.graphqlcop.inql.BatchQueryGenerator_littlespidy;
import com.littlespidy.graphqlcop.inql.CycleScanner_littlespidy;
import com.littlespidy.graphqlcop.inql.PoiFinding_littlespidy;
import com.littlespidy.graphqlcop.inql.PoiScanner_littlespidy;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public class SchemaIntelligenceSubTab_littlespidy extends JPanel {
    private final Supplier<String> schemaSupplier;

    // POI Components
    private final DefaultTableModel poiTableModel;
    private final JTable poiTable;
    private final TableRowSorter<DefaultTableModel> poiSorter;
    private final List<PoiFinding_littlespidy> allPoiFindings = new ArrayList<>();

    // Cycle Components
    private final DefaultTableModel cycleTableModel;
    private final JTable cycleTable;
    private final JTextArea cycleQueryArea;
    private final List<CycleScanner_littlespidy.CycleFinding> detectedCycles = new ArrayList<>();

    // Batch Components
    private final JTextArea batchInputArea;
    private final JSpinner batchCountSpinner;
    private final JRadioButton arrayBatchRadio;
    private final JRadioButton aliasBatchRadio;
    private final JTextArea batchOutputArea;

    public SchemaIntelligenceSubTab_littlespidy(Supplier<String> schemaSupplier) {
        super(new BorderLayout());
        this.schemaSupplier = schemaSupplier;

        JTabbedPane tabs = new JTabbedPane();

        // 1. POI Tab
        JPanel poiPanel = new JPanel(new BorderLayout(4, 4));
        JPanel poiToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton scanPoiBtn = new JButton("Analyze Schema for Points of Interest");
        poiToolbar.add(scanPoiBtn);

        poiToolbar.add(new JLabel("Category Filter:"));
        String[] categories = {"All", "Auth", "Privileged", "PII", "Payment", "Database", "Debugging", "Files"};
        JComboBox<String> categoryCombo = new JComboBox<>(categories);
        poiToolbar.add(categoryCombo);

        poiPanel.add(poiToolbar, BorderLayout.NORTH);

        String[] poiCols = {"Category", "Type", "Field", "Return Type", "Matched Pattern"};
        poiTableModel = new DefaultTableModel(poiCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        poiTable = new JTable(poiTableModel);
        poiSorter = new TableRowSorter<>(poiTableModel);
        poiTable.setRowSorter(poiSorter);
        poiPanel.add(new JScrollPane(poiTable), BorderLayout.CENTER);

        // 2. Cycle Detection Tab
        JPanel cyclePanel = new JPanel(new BorderLayout(4, 4));
        JPanel cycleToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton runCyclesBtn = new JButton("Scan for Circular Relationships (DoS)");
        cycleToolbar.add(runCyclesBtn);
        cyclePanel.add(cycleToolbar, BorderLayout.NORTH);

        String[] cycleCols = {"#", "Root Type", "Cycle Path"};
        cycleTableModel = new DefaultTableModel(cycleCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        cycleTable = new JTable(cycleTableModel);
        cycleTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane cycleTableScroll = new JScrollPane(cycleTable);
        cycleTableScroll.setBorder(BorderFactory.createTitledBorder("Detected Cyclic Graph Dependencies"));

        cycleQueryArea = new JTextArea();
        cycleQueryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cycleQueryArea.setEditable(false);
        JScrollPane cycleQueryScroll = new JScrollPane(cycleQueryArea);
        cycleQueryScroll.setBorder(BorderFactory.createTitledBorder("Generated Cyclic Amplification Query"));

        JSplitPane cycleSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, cycleTableScroll, cycleQueryScroll);
        cycleSplit.setResizeWeight(0.4);
        cyclePanel.add(cycleSplit, BorderLayout.CENTER);

        // 3. Batch Queries Tab
        JPanel batchPanel = new JPanel(new BorderLayout(4, 4));
        JPanel batchConfigPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        batchConfigPanel.add(new JLabel("Batch Count:"));
        batchCountSpinner = new JSpinner(new SpinnerNumberModel(10, 2, 500, 5));
        batchConfigPanel.add(batchCountSpinner);

        arrayBatchRadio = new JRadioButton("Array-Based Batch", true);
        aliasBatchRadio = new JRadioButton("Alias-Based Batch", false);
        ButtonGroup batchGroup = new ButtonGroup();
        batchGroup.add(arrayBatchRadio);
        batchGroup.add(aliasBatchRadio);
        batchConfigPanel.add(arrayBatchRadio);
        batchConfigPanel.add(aliasBatchRadio);

        JButton generateBatchBtn = new JButton("Generate Batch Payload");
        batchConfigPanel.add(generateBatchBtn);
        batchPanel.add(batchConfigPanel, BorderLayout.NORTH);

        batchInputArea = new JTextArea("query {\n  user(id: 1) {\n    name\n    email\n  }\n}");
        batchInputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane batchInputScroll = new JScrollPane(batchInputArea);
        batchInputScroll.setBorder(BorderFactory.createTitledBorder("Template Query"));

        batchOutputArea = new JTextArea();
        batchOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane batchOutputScroll = new JScrollPane(batchOutputArea);
        batchOutputScroll.setBorder(BorderFactory.createTitledBorder("Generated Batch Attack Payload"));

        JSplitPane batchSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, batchInputScroll, batchOutputScroll);
        batchSplit.setResizeWeight(0.45);
        batchPanel.add(batchSplit, BorderLayout.CENTER);

        tabs.addTab("Points of Interest (POI)", poiPanel);
        tabs.addTab("Cycle Detection", cyclePanel);
        tabs.addTab("Batch Queries Generator", batchPanel);
        add(tabs, BorderLayout.CENTER);

        // Action Handlers
        scanPoiBtn.addActionListener(e -> runPoiScan());
        categoryCombo.addActionListener(e -> {
            String selected = (String) categoryCombo.getSelectedItem();
            if ("All".equals(selected) || selected == null) {
                poiSorter.setRowFilter(null);
            } else {
                poiSorter.setRowFilter(RowFilter.regexFilter(selected, 0));
            }
        });

        runCyclesBtn.addActionListener(e -> runCycleScan());
        cycleTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = cycleTable.getSelectedRow();
                if (row >= 0 && row < detectedCycles.size()) {
                    cycleQueryArea.setText(detectedCycles.get(row).recursionQuery);
                }
            }
        });

        generateBatchBtn.addActionListener(e -> {
            int count = (Integer) batchCountSpinner.getValue();
            String query = batchInputArea.getText().trim();
            if (arrayBatchRadio.isSelected()) {
                batchOutputArea.setText(BatchQueryGenerator_littlespidy.generateArrayBatch(query, count));
            } else {
                batchOutputArea.setText(BatchQueryGenerator_littlespidy.generateAliasBatch(query, count));
            }
        });
    }

    public void runPoiScan() {
        String schema = schemaSupplier.get();
        if (schema == null || schema.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Introspection schema not available. Please retrieve introspection first.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        allPoiFindings.clear();
        poiTableModel.setRowCount(0);
        List<PoiFinding_littlespidy> findings = PoiScanner_littlespidy.scanSchema(schema);
        allPoiFindings.addAll(findings);

        for (PoiFinding_littlespidy f : findings) {
            poiTableModel.addRow(new Object[]{
                    f.getCategory(),
                    f.getTypeName(),
                    f.getFieldName(),
                    f.getReturnType(),
                    f.getMatchedKeyword()
            });
        }
    }

    public void runCycleScan() {
        String schema = schemaSupplier.get();
        if (schema == null || schema.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Introspection schema not available. Please retrieve introspection first.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        detectedCycles.clear();
        cycleTableModel.setRowCount(0);
        cycleQueryArea.setText("");

        List<CycleScanner_littlespidy.CycleFinding> cycles = CycleScanner_littlespidy.detectCycles(schema, 6);
        detectedCycles.addAll(cycles);

        for (int i = 0; i < cycles.size(); i++) {
            CycleScanner_littlespidy.CycleFinding c = cycles.get(i);
            cycleTableModel.addRow(new Object[]{
                    i + 1,
                    c.rootType,
                    c.getPathDisplay()
            });
        }

        if (!cycles.isEmpty()) {
            cycleTable.setRowSelectionInterval(0, 0);
        } else {
            cycleQueryArea.setText("# No cyclic graph dependencies detected in the provided schema.");
        }
    }
}
