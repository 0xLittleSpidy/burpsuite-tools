// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.InjectionSettings;
import com.littlespidy.payloadinjector.model.ParamPayloadEntry;
import com.littlespidy.payloadinjector.model.ParamPayloadStore;
import com.littlespidy.payloadinjector.model.PayloadFileService_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Reusable UI tab for managing and configuring parameter-based payloads (XSS, CSTI, SQL).
 * Displays payloads in an interactive table backed by its dedicated JSON store.
 * Supports Import, Copy All, Deduplication, and Burp-style Ascending/Descending column sorting.
 *
 * @author littlespidy
 */
public class ParamPayloadTab extends JPanel {

    private final String categoryTitle;
    private final ParamPayloadStore store;
    private final InjectionSettings settings;

    private final PayloadTableModel tableModel;
    private final JTable table;
    private final JLabel statusLabel;

    public ParamPayloadTab(String categoryTitle, ParamPayloadStore store, InjectionSettings settings) {
        this.categoryTitle = categoryTitle;
        this.store = store;
        this.settings = settings;

        setLayout(new BorderLayout(5, 5));
        setBorder(new EmptyBorder(8, 8, 8, 8));

        // ── Top Section: Action Toolbar & Injection Settings ──
        JPanel topContainer = new JPanel(new BorderLayout(0, 4));

        // 1. Actions Toolbar
        JToolBar actionsBar = new JToolBar();
        actionsBar.setFloatable(false);
        actionsBar.setBorder(new EmptyBorder(2, 4, 2, 4));

        JButton addBtn = new JButton("Add Payload");
        addBtn.addActionListener(e -> openAddDialog());
        actionsBar.add(addBtn);

        actionsBar.addSeparator(new Dimension(6, 0));

        JButton editBtn = new JButton("Edit Selected");
        editBtn.addActionListener(e -> openEditDialog());
        actionsBar.add(editBtn);

        actionsBar.addSeparator(new Dimension(6, 0));

        JButton deleteBtn = new JButton("Delete Selected");
        deleteBtn.addActionListener(e -> deleteSelected());
        actionsBar.add(deleteBtn);

        actionsBar.addSeparator(new Dimension(6, 0));

        JButton importBtn = new JButton("Import");
        importBtn.setToolTipText("Import payloads from a .txt file (one per line)");
        importBtn.addActionListener(e -> importPayloads());
        actionsBar.add(importBtn);

        actionsBar.addSeparator(new Dimension(6, 0));

        JButton copyAllBtn = new JButton("Copy All");
        copyAllBtn.setToolTipText("Copy all payload templates to clipboard");
        copyAllBtn.addActionListener(e -> copyAllPayloads());
        actionsBar.add(copyAllBtn);

        actionsBar.addSeparator(new Dimension(6, 0));

        JButton dedupBtn = new JButton("Deduplicate");
        dedupBtn.setToolTipText("Remove duplicate payloads and create safe backup files");
        dedupBtn.addActionListener(e -> deduplicatePayloads());
        actionsBar.add(dedupBtn);

        actionsBar.addSeparator(new Dimension(12, 0));

        JButton reloadBtn = new JButton("Reload from JSON");
        reloadBtn.addActionListener(e -> {
            store.reload();
            updateStatusLabel();
        });
        actionsBar.add(reloadBtn);

        actionsBar.addSeparator(new Dimension(12, 0));

        statusLabel = new JLabel();
        statusLabel.setForeground(new Color(100, 100, 100));
        actionsBar.add(statusLabel);

        actionsBar.add(Box.createHorizontalGlue());
        actionsBar.add(new JLabel("<html><i>File: " + store.getFileName() + "</i></html>  "));

        topContainer.add(actionsBar, BorderLayout.NORTH);

        // 2. Settings Bar
        JPanel settingsPanel = createSettingsPanel();
        topContainer.add(settingsPanel, BorderLayout.SOUTH);

        add(topContainer, BorderLayout.NORTH);

        // ── Center Section: Payloads Table ──
        tableModel = new PayloadTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(24);
        table.setFont(table.getFont().deriveFont(13f));
        table.getTableHeader().setFont(table.getFont().deriveFont(Font.BOLD, 13f));

        table.getColumnModel().getColumn(0).setPreferredWidth(160); // Name
        table.getColumnModel().getColumn(1).setPreferredWidth(320); // Payload Value
        table.getColumnModel().getColumn(2).setPreferredWidth(220); // Description
        table.getColumnModel().getColumn(3).setPreferredWidth(100); // Source Type
        table.getColumnModel().getColumn(4).setPreferredWidth(130); // Source File

        // Burp-style sorting: toggle between ASCENDING and DESCENDING
        TableRowSorter<PayloadTableModel> sorter = new TableRowSorter<>(tableModel) {
            @Override
            public void toggleSortOrder(int column) {
                List<? extends SortKey> sortKeys = getSortKeys();
                if (!sortKeys.isEmpty() && sortKeys.get(0).getColumn() == column) {
                    if (sortKeys.get(0).getSortOrder() == SortOrder.ASCENDING) {
                        setSortKeys(List.of(new RowSorter.SortKey(column, SortOrder.DESCENDING)));
                        return;
                    } else {
                        setSortKeys(List.of(new RowSorter.SortKey(column, SortOrder.ASCENDING)));
                        return;
                    }
                }
                setSortKeys(List.of(new RowSorter.SortKey(column, SortOrder.ASCENDING)));
            }
        };
        sorter.setSortsOnUpdates(true);
        for (int i = 0; i < tableModel.getColumnCount(); i++) {
            sorter.setComparator(i, String.CASE_INSENSITIVE_ORDER);
        }
        table.setRowSorter(sorter);

        // Custom Header Renderer for "Payload Value" column with "Copy All" button
        setupPayloadColumnHeaderButton();

        // Double click to edit
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRow() != -1) {
                    openEditDialog();
                }
            }
        });

        store.addChangeListener(() -> SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            updateStatusLabel();
        }));

        add(new JScrollPane(table), BorderLayout.CENTER);
        updateStatusLabel();
    }

    private void setupPayloadColumnHeaderButton() {
        TableCellRenderer defaultRenderer = table.getTableHeader().getDefaultRenderer();

        table.getColumnModel().getColumn(1).setHeaderRenderer(new TableCellRenderer() {
            private final JPanel panel = new JPanel(new BorderLayout(4, 0));
            private final JLabel titleLabel = new JLabel();
            private final JButton copyBtn = new JButton("Copy All");

            {
                panel.setOpaque(false);
                copyBtn.setFont(copyBtn.getFont().deriveFont(10f));
                copyBtn.setMargin(new Insets(1, 4, 1, 4));
                copyBtn.setFocusable(false);
                panel.add(titleLabel, BorderLayout.CENTER);
                panel.add(copyBtn, BorderLayout.EAST);
            }

            @Override
            public Component getTableCellRendererComponent(JTable t, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = defaultRenderer.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if (c instanceof JLabel l) {
                    titleLabel.setText(l.getText());
                    titleLabel.setIcon(l.getIcon());
                    titleLabel.setFont(l.getFont());
                    titleLabel.setForeground(l.getForeground());
                    titleLabel.setHorizontalAlignment(l.getHorizontalAlignment());
                } else {
                    titleLabel.setText(value != null ? value.toString() : "");
                }
                panel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4));
                return panel;
            }
        });

        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int viewCol = table.getTableHeader().columnAtPoint(e.getPoint());
                if (viewCol == 1) {
                    Rectangle rect = table.getTableHeader().getHeaderRect(viewCol);
                    int btnWidth = 65;
                    int btnHeight = 20;
                    Rectangle btnBounds = new Rectangle(
                            rect.x + rect.width - btnWidth - 4,
                            rect.y + (rect.height - btnHeight) / 2,
                            btnWidth,
                            btnHeight
                    );
                    if (btnBounds.contains(e.getPoint())) {
                        copyAllPayloads();
                        e.consume();
                    }
                }
            }
        });
    }

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        panel.setBorder(BorderFactory.createCompoundBorder(
                new TitledBorder(categoryTitle + " Injection Rules & Parameter Scope"),
                new EmptyBorder(2, 6, 2, 6)
        ));

        // Insertion mode
        panel.add(new JLabel("Mode:"));
        JComboBox<InjectionSettings.InjectionMode> modeCombo = new JComboBox<>(InjectionSettings.InjectionMode.values());
        modeCombo.setSelectedItem(settings.getInjectionMode());
        modeCombo.addActionListener(e -> settings.setInjectionMode((InjectionSettings.InjectionMode) modeCombo.getSelectedItem()));
        panel.add(modeCombo);

        panel.add(new JSeparator(SwingConstants.VERTICAL));

        // Encoding mode
        panel.add(new JLabel("Encoding:"));
        JComboBox<InjectionSettings.EncodingMode> encCombo = new JComboBox<>(InjectionSettings.EncodingMode.values());
        encCombo.setSelectedItem(settings.getEncodingMode());
        encCombo.addActionListener(e -> settings.setEncodingMode((InjectionSettings.EncodingMode) encCombo.getSelectedItem()));
        panel.add(encCombo);

        panel.add(new JSeparator(SwingConstants.VERTICAL));

        // Parameter type checkboxes
        panel.add(new JLabel("Targets:"));
        JCheckBox cbUrl = new JCheckBox("URL", settings.isTargetUrlParams());
        cbUrl.addActionListener(e -> settings.setTargetUrlParams(cbUrl.isSelected()));
        panel.add(cbUrl);

        JCheckBox cbBody = new JCheckBox("Body", settings.isTargetBodyParams());
        cbBody.addActionListener(e -> settings.setTargetBodyParams(cbBody.isSelected()));
        panel.add(cbBody);

        JCheckBox cbJson = new JCheckBox("JSON", settings.isTargetJsonParams());
        cbJson.addActionListener(e -> settings.setTargetJsonParams(cbJson.isSelected()));
        panel.add(cbJson);

        JCheckBox cbCookie = new JCheckBox("Cookie", settings.isTargetCookieParams());
        cbCookie.addActionListener(e -> settings.setTargetCookieParams(cbCookie.isSelected()));
        panel.add(cbCookie);

        return panel;
    }

    private void openAddDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        AddEditParamPayloadDialog dialog = new AddEditParamPayloadDialog(owner, categoryTitle, null);
        dialog.setVisible(true);

        ParamPayloadEntry result = dialog.getResult();
        if (result != null) {
            store.addEntry(result);
        }
    }

    private void openEditDialog() {
        int viewRow = table.getSelectedRow();
        if (viewRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a payload to edit.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        ParamPayloadEntry existing = store.getEntries().get(modelRow);

        Window owner = SwingUtilities.getWindowAncestor(this);
        AddEditParamPayloadDialog dialog = new AddEditParamPayloadDialog(owner, categoryTitle, existing);
        dialog.setVisible(true);

        ParamPayloadEntry result = dialog.getResult();
        if (result != null) {
            store.updateEntry(modelRow, result);
        }
    }

    private void deleteSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a payload to delete.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        ParamPayloadEntry entry = store.getEntries().get(modelRow);

        int confirm = JOptionPane.showConfirmDialog(this,
                "Delete " + categoryTitle + " payload \"" + entry.getName() + "\"?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            store.removeEntry(modelRow);
        }
    }

    private void importPayloads() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Payloads (.txt)");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text Files (*.txt)", "txt"));
        chooser.setAcceptAllFileFilterUsed(false);

        int ret = chooser.showOpenDialog(this);
        if (ret != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File selectedFile = chooser.getSelectedFile();
        try {
            List<ParamPayloadEntry> imported = PayloadFileService_littlespidy.importPayloadsFromTxt(selectedFile);
            store.addEntries(imported);
            updateStatusLabel();
            JOptionPane.showMessageDialog(this,
                    "Successfully imported " + imported.size() + " payload(s) from:\n" + selectedFile.getName(),
                    "Import Successful",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to import payloads:\n" + ex.getMessage(),
                    "Import Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    public void copyAllPayloads() {
        int rowCount = table.getRowCount();
        if (rowCount == 0) {
            JOptionPane.showMessageDialog(this, "No payloads to copy.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        List<ParamPayloadEntry> entriesToCopy = new ArrayList<>();
        for (int i = 0; i < rowCount; i++) {
            int modelRow = table.convertRowIndexToModel(i);
            entriesToCopy.add(store.getEntries().get(modelRow));
        }

        try {
            int count = PayloadFileService_littlespidy.copyPayloadsToClipboard(entriesToCopy);
            statusLabel.setText("Copied " + count + " payload(s) to clipboard");
            JOptionPane.showMessageDialog(this,
                    "Successfully copied " + count + " payload(s) to clipboard.",
                    "Copy All",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to copy payloads to clipboard:\n" + ex.getMessage(),
                    "Clipboard Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void deduplicatePayloads() {
        List<ParamPayloadEntry> currentEntries = store.getEntries();
        if (currentEntries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "The payload list is empty.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to deduplicate " + categoryTitle + " payloads?\n" +
                "Identical payload templates will be removed, favoring entries with descriptions.\n" +
                "Removed entries and deduplicated list will be safely backed up to disk.",
                "Confirm Deduplication",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }

        try {
            Path backupDir = store.resolveStorageDirectory();
            PayloadFileService_littlespidy.DeduplicationResult_littlespidy result =
                    PayloadFileService_littlespidy.deduplicate(currentEntries, backupDir, categoryTitle);

            if (result.removedCount() == 0) {
                JOptionPane.showMessageDialog(this,
                        "No duplicate payloads found.\nAll " + result.remainingCount() + " payloads are unique.",
                        "Deduplication Complete",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // Only update the active list once both backup files are safely saved
            store.replaceEntries(result.deduplicatedList());
            updateStatusLabel();

            String msg = "Deduplication Complete:\n" +
                    "- Duplicates removed: " + result.removedCount() + "\n" +
                    "- Unique payloads remaining: " + result.remainingCount() + "\n\n" +
                    "Files created:\n" +
                    "- Removed entries: " + result.removedFilePath().getFileName() + "\n" +
                    "- Deduplicated list: " + result.deduplicatedFilePath().getFileName() + "\n\n" +
                    "Location: " + backupDir.toAbsolutePath();

            JOptionPane.showMessageDialog(this, msg, "Deduplication Summary", JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Deduplication failed:\n" + ex.getMessage() + "\nNo payloads were removed.",
                    "Deduplication Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateStatusLabel() {
        int count = store.getEntries().size();
        statusLabel.setText(count + " payload" + (count == 1 ? "" : "s") + " loaded");
    }

    public JTable getTable() {
        return table;
    }

    public PayloadTableModel getTableModel() {
        return tableModel;
    }

    // ── Inner Table Model ──

    public class PayloadTableModel extends AbstractTableModel {
        private final String[] columns = {"Name", "Payload Value", "Description", "Source Type", "Source File"};

        @Override public int getRowCount() { return store.getEntries().size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Class<?> getColumnClass(int col) {
            return String.class;
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return false;
        }

        @Override
        public Object getValueAt(int row, int col) {
            List<ParamPayloadEntry> list = store.getEntries();
            if (row < 0 || row >= list.size()) return null;
            ParamPayloadEntry e = list.get(row);
            return switch (col) {
                case 0 -> e.getName();
                case 1 -> e.getTemplate();
                case 2 -> e.getDescription();
                case 3 -> e.getSourceType();
                case 4 -> e.getSourceFile();
                default -> null;
            };
        }
    }
}
