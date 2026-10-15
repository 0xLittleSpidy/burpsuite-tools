// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.littlespidy.jwtcomparator.model.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

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
    private final JTextField ignoreClaimsField;
    private final JLabel summaryLabel;

    private final JPanel detailContainer;
    private final JLabel detailTitleLabel;
    private final JTabbedPane detailTabs;

    private ComparisonResult currentResult;

    public ComparisonPanel() {
        setLayout(new BorderLayout(0, 5));

        // 1. Top Section: Token Slots in horizontal columns (left to right)
        slotsContainer = new TokenSlotsContainer(this);
        slotsContainer.setBorder(BorderFactory.createTitledBorder("Token Comparison Slots (Columns Left to Right)"));
        slotsContainer.setPreferredSize(new Dimension(800, 270));

        // 2. Middle: Matrix Toolbar
        JPanel matrixToolbar = new JPanel(new BorderLayout(8, 4));
        matrixToolbar.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        JPanel filterControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        filterControls.add(new JLabel("Search:"));
        searchField = new JTextField(12);
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

        filterControls.add(new JLabel("Ignore:"));
        ignoreClaimsField = new JTextField("exp, iat", 10);
        ignoreClaimsField.setToolTipText("Comma-separated claim keys to exclude from 'Differences Only' view (e.g. exp, iat, jti)");
        ignoreClaimsField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        filterControls.add(ignoreClaimsField);

        JButton configIgnoreBtn = new JButton("⚙️");
        configIgnoreBtn.setToolTipText("Configure Ignored Claims with presets (exp, iat, nbf, jti, auth_time)");
        configIgnoreBtn.setMargin(new Insets(2, 5, 2, 5));
        configIgnoreBtn.addActionListener(e -> showIgnoreConfigDialog());
        filterControls.add(configIgnoreBtn);

        summaryLabel = new JLabel("Claims: 0 total | 0 differences");
        summaryLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        filterControls.add(summaryLabel);

        matrixToolbar.add(filterControls, BorderLayout.WEST);

        JPanel actionControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));

        JButton downloadTsvBtn = new JButton("💾 Download TSV");
        downloadTsvBtn.setToolTipText("Download comparison matrix to a .tsv file");
        downloadTsvBtn.addActionListener(e -> downloadTsvReport());

        JButton copyTsvBtn = new JButton("📋 Copy TSV");
        copyTsvBtn.setToolTipText("Copy comparison table to clipboard as TSV");
        copyTsvBtn.addActionListener(e -> copyTsvReport());

        JButton exportJsonBtn = new JButton("💾 Export JSON");
        exportJsonBtn.setToolTipText("Save token slots and names to a JSON file");
        exportJsonBtn.addActionListener(e -> slotsContainer.exportJsonSession());

        JButton importJsonBtn = new JButton("📂 Import JSON");
        importJsonBtn.setToolTipText("Load tokens and slot names from a saved JSON file");
        importJsonBtn.addActionListener(e -> slotsContainer.importJsonSession());

        JButton refreshBtn = new JButton("🔄 Refresh");
        refreshBtn.addActionListener(e -> refreshComparison());

        actionControls.add(downloadTsvBtn);
        actionControls.add(copyTsvBtn);
        actionControls.add(exportJsonBtn);
        actionControls.add(importJsonBtn);
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

        comparisonTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                handleTablePopup(e);
            }
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                handleTablePopup(e);
            }
            private void handleTablePopup(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = comparisonTable.rowAtPoint(e.getPoint());
                    if (r >= 0 && !comparisonTable.isRowSelected(r)) {
                        comparisonTable.setRowSelectionInterval(r, r);
                    }
                    showTableContextMenu(e);
                }
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
        JSplitPane masterSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, slotsContainer, centerPanel);
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
        if (slotsContainer == null) {
            return;
        }
        List<JWTTokenModel> tokens = slotsContainer.getTokens();
        currentResult = ComparisonResult.compute(tokens);
        applyFilter();
    }

    private synchronized void applyFilter() {
        if (currentResult == null || searchField == null || diffFilterCombo == null || sectionFilterCombo == null || tableModel == null || summaryLabel == null || ignoreClaimsField == null) {
            return;
        }

        String search = searchField.getText().trim();
        String diffMode = (String) diffFilterCombo.getSelectedItem();
        String sectionMode = (String) sectionFilterCombo.getSelectedItem();
        java.util.Set<String> ignored = getIgnoredClaimKeys();

        List<ComparisonRow> filtered = currentResult.filter(sectionMode, diffMode, search, ignored);
        List<JWTTokenModel> tokens = slotsContainer.getTokens();

        tableModel.setData(tokens, filtered);

        int ignoredDiffCount = currentResult.countIgnoredDifferences(ignored);
        if ("Differences Only".equalsIgnoreCase(diffMode) && ignoredDiffCount > 0) {
            summaryLabel.setText(String.format("Claims: %d total | %d differences shown (%d ignored: %s) | %d matches",
                    currentResult.getTotalCount(),
                    filtered.size(),
                    ignoredDiffCount,
                    String.join(", ", ignored),
                    currentResult.getIdenticalCount()
            ));
        } else {
            summaryLabel.setText(String.format("Claims: %d total | %d differences (%d mismatches, %d missing) | %d matches",
                    currentResult.getTotalCount(),
                    currentResult.getDifferencesCount(),
                    currentResult.getMismatchCount(),
                    currentResult.getPartialCount(),
                    currentResult.getIdenticalCount()
            ));
        }

        updateDetailInspector();
    }

    public java.util.Set<String> getIgnoredClaimKeys() {
        java.util.Set<String> set = new java.util.LinkedHashSet<>();
        if (ignoreClaimsField != null) {
            String text = ignoreClaimsField.getText();
            if (text != null && !text.trim().isEmpty()) {
                String[] parts = text.split("[,;\\s]+");
                for (String p : parts) {
                    if (!p.trim().isEmpty()) {
                        set.add(p.trim().toLowerCase());
                    }
                }
            }
        }
        return set;
    }

    public void setIgnoredClaims(java.util.Collection<String> keys) {
        if (ignoreClaimsField != null) {
            if (keys != null) {
                ignoreClaimsField.setText(String.join(", ", keys));
            } else {
                ignoreClaimsField.setText("");
            }
        }
        applyFilter();
    }

    public void addIgnoredClaim(String claimKey) {
        if (claimKey == null || claimKey.trim().isEmpty()) return;
        java.util.Set<String> set = getIgnoredClaimKeys();
        set.add(claimKey.trim().toLowerCase());
        if (ignoreClaimsField != null) {
            ignoreClaimsField.setText(String.join(", ", set));
        }
        applyFilter();
    }

    public void removeIgnoredClaim(String claimKey) {
        if (claimKey == null || claimKey.trim().isEmpty()) return;
        java.util.Set<String> set = getIgnoredClaimKeys();
        set.remove(claimKey.trim().toLowerCase());
        if (ignoreClaimsField != null) {
            ignoreClaimsField.setText(String.join(", ", set));
        }
        applyFilter();
    }

    @Override
    public void onIgnoredClaimsImported(List<String> ignoredClaims) {
        if (ignoredClaims != null && !ignoredClaims.isEmpty()) {
            setIgnoredClaims(ignoredClaims);
        }
    }

    @Override
    public java.util.Set<String> getIgnoredClaimsForExport() {
        return getIgnoredClaimKeys();
    }

    private void showTableContextMenu(java.awt.event.MouseEvent e) {
        int selectedRow = comparisonTable.getSelectedRow();
        if (selectedRow < 0) return;
        int modelRow = comparisonTable.convertRowIndexToModel(selectedRow);
        ComparisonRow row = tableModel.getRowAt(modelRow);
        if (row == null) return;

        String claimKey = row.getClaimKey();
        java.util.Set<String> currentIgnored = getIgnoredClaimKeys();
        boolean isIgnored = currentIgnored.contains(claimKey.toLowerCase());

        JPopupMenu menu = new JPopupMenu();

        if (isIgnored) {
            JMenuItem unignoreItem = new JMenuItem("✔ Unignore Claim '" + claimKey + "'");
            unignoreItem.setToolTipText("Show '" + claimKey + "' again in 'Differences Only' view");
            unignoreItem.addActionListener(ev -> removeIgnoredClaim(claimKey));
            menu.add(unignoreItem);
        } else {
            JMenuItem ignoreItem = new JMenuItem("🚫 Ignore Claim '" + claimKey + "' in Differences");
            ignoreItem.setToolTipText("Exclude '" + claimKey + "' when 'Differences Only' filter is active");
            ignoreItem.addActionListener(ev -> addIgnoredClaim(claimKey));
            menu.add(ignoreItem);
        }

        menu.addSeparator();

        JMenuItem configItem = new JMenuItem("⚙️ Configure Ignored Claims...");
        configItem.addActionListener(ev -> showIgnoreConfigDialog());
        menu.add(configItem);

        JMenuItem copyClaimItem = new JMenuItem("📋 Copy Claim Key (" + claimKey + ")");
        copyClaimItem.addActionListener(ev -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(claimKey), null);
        });
        menu.add(copyClaimItem);

        menu.show(comparisonTable, e.getX(), e.getY());
    }

    public void showIgnoreConfigDialog() {
        if (GraphicsEnvironment.isHeadless()) return;

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this),
                "Configure Ignored Claims for Differences View",
                Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(500, 360);
        dialog.setLocationRelativeTo(this);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        JLabel info = new JLabel("<html>Ignored claims are hidden when the <b>Differences Only</b> filter is selected.<br>"
                + "Use this to eliminate noise from expected timestamp drift or dynamic nonces.</html>");
        info.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        content.add(info);
        content.add(Box.createVerticalStrut(10));

        java.util.Set<String> activeIgnored = getIgnoredClaimKeys();
        JCheckBox cbExp = new JCheckBox("exp (Expiration Time)", activeIgnored.contains("exp"));
        JCheckBox cbIat = new JCheckBox("iat (Issued At Time)", activeIgnored.contains("iat"));
        JCheckBox cbNbf = new JCheckBox("nbf (Not Before Time)", activeIgnored.contains("nbf"));
        JCheckBox cbJti = new JCheckBox("jti (JWT Unique ID / Nonce)", activeIgnored.contains("jti"));
        JCheckBox cbAuthTime = new JCheckBox("auth_time (Authentication Time)", activeIgnored.contains("auth_time"));

        JPanel presetPanel = new JPanel(new GridLayout(0, 2, 6, 4));
        presetPanel.setBorder(BorderFactory.createTitledBorder("Common Noisy Claims"));
        presetPanel.add(cbExp);
        presetPanel.add(cbIat);
        presetPanel.add(cbNbf);
        presetPanel.add(cbJti);
        presetPanel.add(cbAuthTime);
        content.add(presetPanel);
        content.add(Box.createVerticalStrut(10));

        java.util.Set<String> standardKeys = java.util.Set.of("exp", "iat", "nbf", "jti", "auth_time");
        List<String> customList = new ArrayList<>();
        for (String k : activeIgnored) {
            if (!standardKeys.contains(k)) {
                customList.add(k);
            }
        }
        JTextField customField = new JTextField(String.join(", ", customList), 25);
        JPanel customPanel = new JPanel(new BorderLayout(5, 4));
        customPanel.setBorder(BorderFactory.createTitledBorder("Additional Custom Claim Keys"));
        customPanel.add(new JLabel("Keys (comma-separated):"), BorderLayout.NORTH);
        customPanel.add(customField, BorderLayout.CENTER);
        content.add(customPanel);

        dialog.add(content, BorderLayout.CENTER);

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton allTimestampsBtn = new JButton("⏱️ Check Timestamps");
        allTimestampsBtn.addActionListener(e -> {
            cbExp.setSelected(true);
            cbIat.setSelected(true);
            cbNbf.setSelected(true);
            cbAuthTime.setSelected(true);
        });

        JButton clearAllBtn = new JButton("Clear All");
        clearAllBtn.addActionListener(e -> {
            cbExp.setSelected(false);
            cbIat.setSelected(false);
            cbNbf.setSelected(false);
            cbJti.setSelected(false);
            cbAuthTime.setSelected(false);
            customField.setText("");
        });

        JButton saveBtn = new JButton("Save & Apply");
        saveBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        saveBtn.addActionListener(e -> {
            java.util.Set<String> newSet = new java.util.LinkedHashSet<>();
            if (cbExp.isSelected()) newSet.add("exp");
            if (cbIat.isSelected()) newSet.add("iat");
            if (cbNbf.isSelected()) newSet.add("nbf");
            if (cbJti.isSelected()) newSet.add("jti");
            if (cbAuthTime.isSelected()) newSet.add("auth_time");

            String customText = customField.getText().trim();
            if (!customText.isEmpty()) {
                String[] parts = customText.split("[,;\\s]+");
                for (String p : parts) {
                    if (!p.trim().isEmpty()) {
                        newSet.add(p.trim().toLowerCase());
                    }
                }
            }

            ignoreClaimsField.setText(String.join(", ", newSet));
            applyFilter();
            dialog.dispose();
        });

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dialog.dispose());

        btnBar.add(allTimestampsBtn);
        btnBar.add(clearAllBtn);
        btnBar.add(saveBtn);
        btnBar.add(cancelBtn);
        dialog.add(btnBar, BorderLayout.SOUTH);

        dialog.setVisible(true);
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

    public String generateTsvContent() {
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
        return sb.toString();
    }

    public void copyTsvReport() {
        String tsv = generateTsvContent();
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(tsv), null);
        JOptionPane.showMessageDialog(this,
                "Comparison TSV successfully copied to clipboard!",
                "TSV Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    public void downloadTsvReport() {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Download Comparison Matrix as TSV");
        chooser.setSelectedFile(new File("jwt-comparison-diff.tsv"));
        chooser.setFileFilter(new FileNameExtensionFilter("Tab-Separated Values (*.tsv)", "tsv"));

        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".tsv")) {
                file = new File(file.getAbsolutePath() + ".tsv");
            }
            try {
                String tsv = generateTsvContent();
                Files.writeString(file.toPath(), tsv, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this,
                        "Comparison TSV report saved to:\n" + file.getAbsolutePath(),
                        "TSV Saved", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Error saving TSV file: " + ex.getMessage(),
                        "Save Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public TokenSlotsContainer getSlotsContainer() {
        return slotsContainer;
    }
}
