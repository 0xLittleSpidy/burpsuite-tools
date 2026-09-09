// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.littlespidy.jwtcomparator.model.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.List;

/**
 * Main interactive comparison panel housing dynamic token slots, diff matrix, and claim inspector.
 */
public class ComparisonPanel extends JPanel implements TokenSlotsContainer.SlotsChangeListener {

    private final TokenSlotsContainer slotsContainer;
    private final ComparisonTableModel tableModel;
    private final JTable comparisonTable;

    private final JTextField searchField;
    private final JComboBox<String> diffFilterCombo;
    private final JComboBox<String> sectionFilterCombo;
    private final JLabel summaryLabel;

    private final JPanel detailContainer;
    private final JLabel detailTitleLabel;
    private final JTabbedPane detailTabs;

    private ComparisonResult currentResult;

    public ComparisonPanel() {
        setLayout(new BorderLayout(0, 5));

        // 1. Top Section: Token Slots in a scrollable panel
        slotsContainer = new TokenSlotsContainer(this);
        JScrollPane slotsScroll = new JScrollPane(slotsContainer);
        slotsScroll.setBorder(BorderFactory.createTitledBorder("Token Slots (N Tokens)"));
        slotsScroll.setPreferredSize(new Dimension(800, 260));

        // 2. Middle: Matrix Toolbar
        JPanel matrixToolbar = new JPanel(new BorderLayout(8, 4));
        matrixToolbar.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        JPanel filterControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        filterControls.add(new JLabel("Search:"));
        searchField = new JTextField(15);
        searchField.setToolTipText("Filter by claim key or value");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        filterControls.add(searchField);

        filterControls.add(new JLabel("View:"));
        diffFilterCombo = new JComboBox<>(new String[]{
                "All Claims",
                "Differences Only",
                "Missing Only",
                "Matches Only"
        });
        diffFilterCombo.setSelectedIndex(0);
        diffFilterCombo.addActionListener(e -> applyFilter());
        filterControls.add(diffFilterCombo);

        filterControls.add(new JLabel("Section:"));
        sectionFilterCombo = new JComboBox<>(new String[]{"All", "Payload", "Header"});
        sectionFilterCombo.addActionListener(e -> applyFilter());
        filterControls.add(sectionFilterCombo);

        summaryLabel = new JLabel("Claims: 0 total | 0 differences");
        summaryLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        filterControls.add(summaryLabel);

        matrixToolbar.add(filterControls, BorderLayout.WEST);

        JPanel actionControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton copyTsvBtn = new JButton("📋 Copy TSV Diff");
        copyTsvBtn.setToolTipText("Copy comparison table to clipboard as TSV");
        copyTsvBtn.addActionListener(e -> copyTsvReport());

        JButton refreshBtn = new JButton("🔄 Refresh");
        refreshBtn.addActionListener(e -> refreshComparison());

        actionControls.add(copyTsvBtn);
        actionControls.add(refreshBtn);
        matrixToolbar.add(actionControls, BorderLayout.EAST);

        // 3. Main Center: Comparison Table
        tableModel = new ComparisonTableModel();
        comparisonTable = new JTable(tableModel);
        comparisonTable.setDefaultRenderer(Object.class, new DiffTableCellRenderer());
        comparisonTable.setRowHeight(24);
        comparisonTable.setAutoCreateRowSorter(true);
        comparisonTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        comparisonTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateDetailInspector();
            }
        });

        JScrollPane tableScroll = new JScrollPane(comparisonTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Claims Comparison Matrix"));

        // 4. Bottom Detail Inspector
        detailContainer = new JPanel(new BorderLayout(5, 5));
        detailContainer.setBorder(BorderFactory.createTitledBorder("Selected Claim Inspector"));
        detailContainer.setPreferredSize(new Dimension(800, 160));

        detailTitleLabel = new JLabel("Select a claim row above to inspect detailed values and timestamp translations.");
        detailTitleLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        detailTitleLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        detailContainer.add(detailTitleLabel, BorderLayout.NORTH);

        detailTabs = new JTabbedPane();
        detailContainer.add(detailTabs, BorderLayout.CENTER);

        // Lower Split: Table on Top, Detail Inspector on Bottom
        JSplitPane tableDetailSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailContainer);
        tableDetailSplit.setResizeWeight(0.7);
        tableDetailSplit.setContinuousLayout(true);

        // Center Panel combining Toolbar + TableDetailSplit
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(matrixToolbar, BorderLayout.NORTH);
        centerPanel.add(tableDetailSplit, BorderLayout.CENTER);

        // Master Vertical Split: Slots on Top, Center Panel on Bottom
        JSplitPane masterSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, slotsScroll, centerPanel);
        masterSplit.setResizeWeight(0.35);
        masterSplit.setContinuousLayout(true);

        add(masterSplit, BorderLayout.CENTER);

        refreshComparison();
    }

    @Override
    public void onSlotsChanged() {
        refreshComparison();
    }

    public synchronized void refreshComparison() {
        List<JWTTokenModel> tokens = slotsContainer.getTokens();
        currentResult = ComparisonResult.compute(tokens);
        applyFilter();
    }

    private synchronized void applyFilter() {
        if (currentResult == null) {
            return;
        }

        String search = searchField.getText().trim();
        String diffMode = (String) diffFilterCombo.getSelectedItem();
        String sectionMode = (String) sectionFilterCombo.getSelectedItem();

        List<ComparisonRow> filtered = currentResult.filter(sectionMode, diffMode, search);
        List<JWTTokenModel> tokens = slotsContainer.getTokens();

        tableModel.setData(tokens, filtered);

        summaryLabel.setText(String.format("Claims: %d total | %d differences (%d mismatches, %d missing) | %d matches",
                currentResult.getTotalCount(),
                currentResult.getDifferencesCount(),
                currentResult.getMismatchCount(),
                currentResult.getPartialCount(),
                currentResult.getIdenticalCount()
        ));

        updateDetailInspector();
    }

    private void updateDetailInspector() {
        int selectedRow = comparisonTable.getSelectedRow();
        if (selectedRow < 0) {
            detailTitleLabel.setText("Select a claim row above to inspect detailed values and timestamp translations.");
            detailTabs.removeAll();
            return;
        }

        int modelRow = comparisonTable.convertRowIndexToModel(selectedRow);
        ComparisonRow row = tableModel.getRowAt(modelRow);
        if (row == null) {
            return;
        }

        detailTitleLabel.setText(String.format("Claim: [%s] %s  |  Status: %s  (%s)",
                row.getSection(),
                row.getClaimKey(),
                row.getDiffType().getDisplayName(),
                row.getDiffType().getDescription()));

        detailTabs.removeAll();

        List<JWTTokenModel> tokens = slotsContainer.getTokens();
        for (JWTTokenModel token : tokens) {
            int slot = token.getSlotIndex();
            String tabTitle = "Token " + slot + " (" + token.getLabel() + ")";

            JTextArea area = new JTextArea();
            area.setEditable(false);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

            if (row.hasValue(slot)) {
                Object raw = row.getRawValue(slot);
                if (row.isTimestamp()) {
                    String tsHuman = token.getTimestampHumanReadable(row.getClaimKey());
                    area.setText("Timestamp Analysis:\n" + tsHuman + "\n\nRaw Value:\n" + raw);
                } else {
                    area.setText(JWTParser.formatClaimValuePretty(raw));
                }
            } else {
                area.setText("[NOT PRESENT IN THIS TOKEN]");
                area.setForeground(Color.GRAY);
            }

            area.setCaretPosition(0);
            detailTabs.addTab(tabTitle, new JScrollPane(area));
        }
    }

    private void copyTsvReport() {
        StringBuilder sb = new StringBuilder();
        int colCount = tableModel.getColumnCount();

        // Header
        for (int c = 0; c < colCount; c++) {
            sb.append(tableModel.getColumnName(c));
            if (c < colCount - 1) sb.append("\t");
        }
        sb.append("\n");

        // Rows
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            for (int c = 0; c < colCount; c++) {
                Object val = tableModel.getValueAt(r, c);
                sb.append(val != null ? val.toString().replace("\t", " ").replace("\n", " ") : "");
                if (c < colCount - 1) sb.append("\t");
            }
            sb.append("\n");
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        JOptionPane.showMessageDialog(this,
                "Comparison TSV successfully copied to clipboard!",
                "TSV Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    public TokenSlotsContainer getSlotsContainer() {
        return slotsContainer;
    }
}
