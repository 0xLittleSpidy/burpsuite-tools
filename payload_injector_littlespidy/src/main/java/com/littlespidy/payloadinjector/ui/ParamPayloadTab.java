// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.InjectionSettings;
import com.littlespidy.payloadinjector.model.ParamPayloadEntry;
import com.littlespidy.payloadinjector.model.ParamPayloadStore;
import com.littlespidy.payloadinjector.model.PayloadFileService_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

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
    private final boolean isPathTraversal;
    private final ParamPayloadStore store;
    private final InjectionSettings settings;

    private final PayloadTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<PayloadTableModel> sorter;
    private final JTextField searchField;
    private final JComboBox<String> platformFilterBox;
    private final JLabel statusLabel;

    public ParamPayloadTab(String categoryTitle, ParamPayloadStore store, InjectionSettings settings) {
        this.categoryTitle = categoryTitle;
        this.isPathTraversal = "Path Traversal".equalsIgnoreCase(categoryTitle);
        this.store = store;
        this.settings = settings;

        setLayout(new BorderLayout(5, 5));
        setBorder(new EmptyBorder(8, 8, 8, 8));

        // -- Top Section: Action Toolbar & Injection Settings --
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

        actionsBar.addSeparator(new Dimension(10, 0));

        JButton reloadBtn = new JButton("Reload from JSON");
        reloadBtn.addActionListener(e -> {
            store.reload();
            applySearchFilter();
            updateStatusLabel();
        });
        actionsBar.add(reloadBtn);

        actionsBar.addSeparator(new Dimension(10, 0));

        // -- Platform Filter (Path Traversal) --
        if (isPathTraversal) {
            actionsBar.add(new JLabel("Platform: "));
            platformFilterBox = new JComboBox<>(new String[]{"All Platforms", "Linux", "Windows"});
            platformFilterBox.setMaximumSize(new Dimension(120, 26));
            platformFilterBox.addActionListener(e -> applySearchFilter());
            actionsBar.add(platformFilterBox);
            actionsBar.addSeparator(new Dimension(8, 0));
        } else {
            platformFilterBox = null;
        }

        // -- Search Bar --
        actionsBar.add(new JLabel("Search: "));
        searchField = new JTextField(15);
        searchField.setToolTipText("Search both payload name and payload value");
        searchField.setMaximumSize(new Dimension(200, 26));
        actionsBar.add(searchField);

        actionsBar.addSeparator(new Dimension(4, 0));

        JButton clearBtn = new JButton("Clear");
        clearBtn.setToolTipText("Clear active search filter");
        clearBtn.addActionListener(e -> {
            searchField.setText("");
            searchField.requestFocusInWindow();
        });
        actionsBar.add(clearBtn);

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

        // -- Center Section: Payloads Table --
        tableModel = new PayloadTableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowHeight(24);
        table.setFont(table.getFont().deriveFont(13f));
        table.getTableHeader().setFont(table.getFont().deriveFont(Font.BOLD, 13f));

        if (isPathTraversal) {
            table.getColumnModel().getColumn(0).setPreferredWidth(180); // Name
            table.getColumnModel().getColumn(1).setPreferredWidth(100); // Platform
            table.getColumnModel().getColumn(2).setPreferredWidth(380); // Payload Value
            table.getColumnModel().getColumn(3).setPreferredWidth(260); // Description

            JComboBox<String> platformBox = new JComboBox<>(new String[]{"Linux", "Windows"});
            table.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(platformBox));
        } else {
            table.getColumnModel().getColumn(0).setPreferredWidth(200); // Name
            table.getColumnModel().getColumn(1).setPreferredWidth(450); // Payload Value
            table.getColumnModel().getColumn(2).setPreferredWidth(280); // Description
        }

        // Burp-style sorting: toggle between ASCENDING and DESCENDING
        sorter = new TableRowSorter<>(tableModel) {
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

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applySearchFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applySearchFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applySearchFilter(); }
        });

        // Custom Header Renderer for "Payload Value" column with "Copy All" button
        setupPayloadColumnHeaderButton();

        // Keyboard Delete shortcut
        table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteSelectedPayloads");
        table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "deleteSelectedPayloads");
        table.getActionMap().put("deleteSelectedPayloads", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                deleteSelected();
            }
        });

        store.addChangeListener(() -> SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            applySearchFilter();
            updateStatusLabel();
        }));

        add(new JScrollPane(table), BorderLayout.CENTER);
        applySearchFilter();
        updateStatusLabel();
    }

    private void setupPayloadColumnHeaderButton() {
        TableCellRenderer defaultRenderer = table.getTableHeader().getDefaultRenderer();
        final int payloadCol = isPathTraversal ? 2 : 1;

        table.getColumnModel().getColumn(payloadCol).setHeaderRenderer(new TableCellRenderer() {
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
                if (viewCol == payloadCol) {
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

        int editCol = isPathTraversal ? 2 : 1;
        table.editCellAt(viewRow, editCol);
        if (table.getEditorComponent() != null) {
            table.getEditorComponent().requestFocusInWindow();
        }
    }

    private void deleteSelected() {
        int[] viewRows = table.getSelectedRows();
        if (viewRows.length == 0) {
            JOptionPane.showMessageDialog(this, "Please select at least one payload to delete.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String confirmMsg = (viewRows.length == 1)
                ? "Delete " + categoryTitle + " payload \"" + store.getEntries().get(table.convertRowIndexToModel(viewRows[0])).getName() + "\"?"
                : "Delete " + viewRows.length + " selected " + categoryTitle + " payloads?";

        int confirm = JOptionPane.showConfirmDialog(this,
                confirmMsg,
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            int[] modelRows = new int[viewRows.length];
            for (int i = 0; i < viewRows.length; i++) {
                modelRows[i] = table.convertRowIndexToModel(viewRows[i]);
            }
            store.removeEntries(modelRows);
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

    public void applySearchFilter() {
        if (sorter == null) return;
        List<RowFilter<PayloadTableModel, Integer>> filters = new ArrayList<>();

        // Platform filter for Path Traversal
        if (isPathTraversal && platformFilterBox != null) {
            String selectedPlatform = (String) platformFilterBox.getSelectedItem();
            if (selectedPlatform != null && !"All Platforms".equalsIgnoreCase(selectedPlatform)) {
                // Column 1 is "Platform" in Path Traversal
                filters.add(RowFilter.regexFilter("(?i)^" + Pattern.quote(selectedPlatform) + "$", 1));
            }
        }

        // Search text: specifically search both Name and Payload Value columns
        String text = (searchField != null) ? searchField.getText().trim() : "";
        if (!text.isEmpty()) {
            int nameCol = 0;
            int payloadCol = isPathTraversal ? 2 : 1;
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(text), nameCol, payloadCol));
        }

        if (filters.isEmpty()) {
            sorter.setRowFilter(null);
        } else if (filters.size() == 1) {
            sorter.setRowFilter(filters.get(0));
        } else {
            sorter.setRowFilter(RowFilter.andFilter(filters));
        }
        updateStatusLabel();
    }

    private void updateStatusLabel() {
        if (statusLabel == null) return;
        int total = tableModel.getRowCount();
        int filtered = table.getRowCount();
        boolean hasText = searchField != null && !searchField.getText().trim().isEmpty();
        boolean hasPlatform = isPathTraversal && platformFilterBox != null
                && !"All Platforms".equalsIgnoreCase((String) platformFilterBox.getSelectedItem());

        if (hasText || hasPlatform) {
            statusLabel.setText("Showing " + filtered + " of " + total + " payloads");
        } else {
            statusLabel.setText(total + " payload" + (total == 1 ? "" : "s") + " loaded");
        }
    }

    public JTextField getSearchField() {
        return searchField;
    }

    public JComboBox<String> getPlatformFilterBox() {
        return platformFilterBox;
    }

    public JTable getTable() {
        return table;
    }

    public PayloadTableModel getTableModel() {
        return tableModel;
    }

    // -- Inner Table Model --

    public class PayloadTableModel extends AbstractTableModel {
        private final String[] columns;

        public PayloadTableModel() {
            if (isPathTraversal) {
                this.columns = new String[]{"Name", "Platform", "Payload Value", "Description"};
            } else {
                this.columns = new String[]{"Name", "Payload Value", "Description"};
            }
        }

        @Override public int getRowCount() { return store.getEntries().size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Class<?> getColumnClass(int col) {
            return String.class;
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return true;
        }

        @Override
        public void setValueAt(Object aValue, int row, int col) {
            List<ParamPayloadEntry> list = store.getEntries();
            if (row < 0 || row >= list.size()) return;
            ParamPayloadEntry e = list.get(row);
            String val = (aValue != null) ? aValue.toString().trim() : "";

            if (isPathTraversal) {
                switch (col) {
                    case 0 -> {
                        if (!val.isEmpty()) e.setName(val);
                    }
                    case 1 -> e.setPlatform("Windows".equalsIgnoreCase(val) ? "Windows" : "Linux");
                    case 2 -> {
                        if (!val.isEmpty()) e.setTemplate(val);
                    }
                    case 3 -> e.setDescription(val);
                }
            } else {
                switch (col) {
                    case 0 -> {
                        if (!val.isEmpty()) e.setName(val);
                    }
                    case 1 -> {
                        if (!val.isEmpty()) e.setTemplate(val);
                    }
                    case 2 -> e.setDescription(val);
                }
            }
            store.save();
            fireTableCellUpdated(row, col);
        }

        @Override
        public Object getValueAt(int row, int col) {
            List<ParamPayloadEntry> list = store.getEntries();
            if (row < 0 || row >= list.size()) return null;
            ParamPayloadEntry e = list.get(row);
            if (isPathTraversal) {
                return switch (col) {
                    case 0 -> e.getName();
                    case 1 -> (e.getPlatform() != null) ? e.getPlatform() : "";
                    case 2 -> e.getTemplate();
                    case 3 -> e.getDescription();
                    default -> null;
                };
            } else {
                return switch (col) {
                    case 0 -> e.getName();
                    case 1 -> e.getTemplate();
                    case 2 -> e.getDescription();
                    default -> null;
                };
            }
        }
    }
}
