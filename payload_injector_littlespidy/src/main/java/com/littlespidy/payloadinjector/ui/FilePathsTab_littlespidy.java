// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy;
import com.littlespidy.payloadinjector.model.FilePathStore_littlespidy;
import com.littlespidy.payloadinjector.model.PayloadFileService_littlespidy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Master File Paths Tab providing categorized management of Linux and Windows target file paths.
 * Positioned as the first tab in the extension UI to cleanly separate reusable path traversal
 * templates from specific operating system target file paths.
 * Features integrated real-time search bars across both subtabs that retain filter state across reloads.
 *
 * @author littlespidy
 */
public class FilePathsTab_littlespidy extends JPanel {

    private final FilePathStore_littlespidy linuxStore;
    private final FilePathStore_littlespidy windowsStore;

    private final FilePathPanel linuxPanel;
    private final FilePathPanel windowsPanel;

    public FilePathsTab_littlespidy(FilePathStore_littlespidy linuxStore, FilePathStore_littlespidy windowsStore) {
        this.linuxStore = linuxStore;
        this.windowsStore = windowsStore;

        setLayout(new BorderLayout());

        JTabbedPane subTabbedPane = new JTabbedPane();
        subTabbedPane.setFont(subTabbedPane.getFont().deriveFont(Font.BOLD, 12f));

        linuxPanel = new FilePathPanel("Linux", linuxStore);
        windowsPanel = new FilePathPanel("Windows", windowsStore);

        subTabbedPane.addTab("Linux File Paths", linuxPanel);
        subTabbedPane.addTab("Windows File Paths", windowsPanel);

        add(subTabbedPane, BorderLayout.CENTER);
    }

    public FilePathPanel getLinuxPanel() {
        return linuxPanel;
    }

    public FilePathPanel getWindowsPanel() {
        return windowsPanel;
    }

    /**
     * Sub-panel managing target file paths for a specific operating system platform.
     */
    public static class FilePathPanel extends JPanel {

        private final String platform;
        private final FilePathStore_littlespidy store;
        private final FilePathTableModel tableModel;
        private final JTable table;
        private final TableRowSorter<FilePathTableModel> sorter;
        private final JTextField searchField;
        private final JLabel statusLabel;

        public FilePathPanel(String platform, FilePathStore_littlespidy store) {
            this.platform = platform;
            this.store = store;

            setLayout(new BorderLayout(5, 5));
            setBorder(new EmptyBorder(8, 8, 8, 8));

            // -- Top Toolbar Section --
            JToolBar actionsBar = new JToolBar();
            actionsBar.setFloatable(false);
            actionsBar.setBorder(new EmptyBorder(2, 4, 2, 4));

            JButton addBtn = new JButton("Add File Path");
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
            importBtn.setToolTipText("Import target paths from a .txt file (one per line)");
            importBtn.addActionListener(e -> importPaths());
            actionsBar.add(importBtn);

            actionsBar.addSeparator(new Dimension(6, 0));

            JButton copyAllBtn = new JButton("Copy All");
            copyAllBtn.setToolTipText("Copy all target file paths to clipboard");
            copyAllBtn.addActionListener(e -> copyAllPaths());
            actionsBar.add(copyAllBtn);

            actionsBar.addSeparator(new Dimension(6, 0));

            JButton dedupBtn = new JButton("Deduplicate");
            dedupBtn.setToolTipText("Remove duplicate target file paths");
            dedupBtn.addActionListener(e -> deduplicatePaths());
            actionsBar.add(dedupBtn);

            actionsBar.addSeparator(new Dimension(10, 0));

            JButton reloadBtn = new JButton("Reload from JSON");
            reloadBtn.addActionListener(e -> {
                store.reload();
                applySearchFilter();
                updateStatusLabel();
            });
            actionsBar.add(reloadBtn);

            actionsBar.addSeparator(new Dimension(12, 0));

            // -- Integrated Search Bar --
            actionsBar.add(new JLabel("Search: "));
            searchField = new JTextField(15);
            searchField.setToolTipText("Filter target paths across all columns");
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

            add(actionsBar, BorderLayout.NORTH);

            // -- Table Setup --
            tableModel = new FilePathTableModel();
            table = new JTable(tableModel);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            table.setRowHeight(24);
            table.setFont(table.getFont().deriveFont(13f));
            table.getTableHeader().setFont(table.getFont().deriveFont(Font.BOLD, 13f));

            table.getColumnModel().getColumn(0).setPreferredWidth(340); // Path
            table.getColumnModel().getColumn(1).setPreferredWidth(180); // Category
            table.getColumnModel().getColumn(2).setPreferredWidth(380); // Description

            // Burp-style sorting toggle
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

            // Search document listener
            searchField.getDocument().addDocumentListener(new DocumentListener() {
                @Override public void insertUpdate(DocumentEvent e) { applySearchFilter(); }
                @Override public void removeUpdate(DocumentEvent e) { applySearchFilter(); }
                @Override public void changedUpdate(DocumentEvent e) { applySearchFilter(); }
            });

            // Keyboard Delete shortcut
            table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                    .put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteSelectedFilePaths");
            table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                    .put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "deleteSelectedFilePaths");
            table.getActionMap().put("deleteSelectedFilePaths", new AbstractAction() {
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

        public void applySearchFilter() {
            String text = (searchField != null) ? searchField.getText().trim() : "";
            if (text.isEmpty()) {
                sorter.setRowFilter(null);
            } else {
                sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
            }
            updateStatusLabel();
        }

        public void updateStatusLabel() {
            if (statusLabel == null) return;
            int total = tableModel.getRowCount();
            int filtered = table.getRowCount();
            if (searchField != null && !searchField.getText().trim().isEmpty()) {
                statusLabel.setText("Showing " + filtered + " of " + total + " paths");
            } else {
                statusLabel.setText(total + " path" + (total == 1 ? "" : "s") + " loaded");
            }
        }

        private void openAddDialog() {
            Window owner = SwingUtilities.getWindowAncestor(this);
            AddEditFilePathDialog_littlespidy dialog = new AddEditFilePathDialog_littlespidy(owner, platform, null);
            dialog.setVisible(true);

            FilePathEntry_littlespidy result = dialog.getResult();
            if (result != null) {
                store.addEntry(result);
            }
        }

        private void openEditDialog() {
            int viewRow = table.getSelectedRow();
            if (viewRow == -1) {
                JOptionPane.showMessageDialog(this, "Please select a target file path to edit.", "Notice", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            table.editCellAt(viewRow, 0);
            if (table.getEditorComponent() != null) {
                table.getEditorComponent().requestFocusInWindow();
            }
        }

        private void deleteSelected() {
            int[] viewRows = table.getSelectedRows();
            if (viewRows.length == 0) {
                JOptionPane.showMessageDialog(this, "Please select at least one target file path to delete.", "Notice", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            String confirmMsg = (viewRows.length == 1)
                    ? "Delete " + platform + " target file path \"" + store.getEntries().get(table.convertRowIndexToModel(viewRows[0])).getPath() + "\"?"
                    : "Delete " + viewRows.length + " selected " + platform + " target file paths?";

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

        private void importPaths() {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Import " + platform + " File Paths (.txt or .json)");
            chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Path Files (*.txt, *.json)", "txt", "json"));
            chooser.setAcceptAllFileFilterUsed(false);

            int ret = chooser.showOpenDialog(this);
            if (ret != JFileChooser.APPROVE_OPTION) {
                return;
            }

            File selectedFile = chooser.getSelectedFile();
            try {
                List<FilePathEntry_littlespidy> imported = new ArrayList<>();
                String content = Files.readString(selectedFile.toPath(), java.nio.charset.StandardCharsets.UTF_8).trim();
                if (selectedFile.getName().toLowerCase().endsWith(".json") || content.startsWith("[")) {
                    com.google.gson.JsonElement parsed = com.google.gson.JsonParser.parseString(content);
                    if (parsed.isJsonArray()) {
                        for (com.google.gson.JsonElement el : parsed.getAsJsonArray()) {
                            if (el.isJsonObject()) {
                                com.google.gson.JsonObject obj = el.getAsJsonObject();
                                String pathVal = obj.has("path") ? obj.get("path").getAsString().trim() : "";
                                String catVal = obj.has("category") ? obj.get("category").getAsString().trim() : "Imported";
                                String descVal = obj.has("description") ? obj.get("description").getAsString().trim() : "";
                                String platVal = obj.has("platform") ? obj.get("platform").getAsString().trim() : platform;
                                if (!pathVal.isEmpty()) {
                                    imported.add(new FilePathEntry_littlespidy(
                                            java.util.UUID.randomUUID().toString(),
                                            pathVal,
                                            catVal.isEmpty() ? "Imported" : catVal,
                                            descVal,
                                            platVal.isEmpty() ? platform : platVal,
                                            true,
                                            "Imported",
                                            selectedFile.getName()
                                    ));
                                }
                            } else if (el.isJsonPrimitive()) {
                                String pathVal = el.getAsString().trim();
                                if (!pathVal.isEmpty()) {
                                    imported.add(new FilePathEntry_littlespidy(
                                            java.util.UUID.randomUUID().toString(),
                                            pathVal,
                                            "Imported",
                                            "",
                                            platform,
                                            true,
                                            "Imported",
                                            selectedFile.getName()
                                    ));
                                }
                            }
                        }
                    }
                } else {
                    List<String> lines = Files.readAllLines(selectedFile.toPath());
                    for (String line : lines) {
                        String trimmed = line.trim();
                        if (!trimmed.isEmpty()) {
                            imported.add(new FilePathEntry_littlespidy(
                                    java.util.UUID.randomUUID().toString(),
                                    trimmed,
                                    "Imported",
                                    "",
                                    platform,
                                    true,
                                    "Imported",
                                    selectedFile.getName()
                            ));
                        }
                    }
                }
                store.addEntries(imported);
                applySearchFilter();
                updateStatusLabel();
                JOptionPane.showMessageDialog(this,
                        "Successfully imported " + imported.size() + " path(s) from:\n" + selectedFile.getName(),
                        "Import Successful",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to import paths:\n" + ex.getMessage(),
                        "Import Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }

        public void copyAllPaths() {
            List<FilePathEntry_littlespidy> current = store.getEntries();
            if (current.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No file paths to copy.", "Notice", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            StringBuilder sb = new StringBuilder();
            for (FilePathEntry_littlespidy e : current) {
                sb.append(e.getPath()).append("\n");
            }

            try {
                java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(sb.toString());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                JOptionPane.showMessageDialog(this,
                        "Successfully copied " + current.size() + " file path(s) to clipboard.",
                        "Copy All",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to copy paths to clipboard:\n" + ex.getMessage(),
                        "Clipboard Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }

        private void deduplicatePaths() {
            List<FilePathEntry_littlespidy> current = store.getEntries();
            if (current.isEmpty()) {
                JOptionPane.showMessageDialog(this, "The file path list is empty.", "Notice", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            LinkedHashSet<String> seen = new LinkedHashSet<>();
            List<FilePathEntry_littlespidy> unique = new ArrayList<>();
            int removed = 0;

            for (FilePathEntry_littlespidy e : current) {
                String norm = e.getPath().toLowerCase();
                if (seen.add(norm)) {
                    unique.add(e);
                } else {
                    removed++;
                }
            }

            if (removed == 0) {
                JOptionPane.showMessageDialog(this,
                        "No duplicate file paths found.\nAll " + current.size() + " paths are unique.",
                        "Deduplication Complete",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            store.replaceEntries(unique);
            applySearchFilter();
            updateStatusLabel();
            JOptionPane.showMessageDialog(this,
                    "Deduplication Complete:\n- Duplicates removed: " + removed + "\n- Unique paths remaining: " + unique.size(),
                    "Deduplication Complete",
                    JOptionPane.INFORMATION_MESSAGE);
        }

        public JTable getTable() {
            return table;
        }

        public FilePathTableModel getTableModel() {
            return tableModel;
        }

        public JTextField getSearchField() {
            return searchField;
        }

        public class FilePathTableModel extends AbstractTableModel {
            private final String[] columns = {"Path", "Category", "Description"};

            @Override public int getRowCount() { return store.getEntries().size(); }
            @Override public int getColumnCount() { return columns.length; }
            @Override public String getColumnName(int col) { return columns[col]; }
            @Override public Class<?> getColumnClass(int col) { return String.class; }
            @Override public boolean isCellEditable(int row, int col) { return true; }

            @Override
            public void setValueAt(Object aValue, int row, int col) {
                List<FilePathEntry_littlespidy> list = store.getEntries();
                if (row < 0 || row >= list.size()) return;
                FilePathEntry_littlespidy e = list.get(row);
                String val = (aValue != null) ? aValue.toString().trim() : "";

                switch (col) {
                    case 0 -> {
                        if (!val.isEmpty()) e.setPath(val);
                    }
                    case 1 -> e.setCategory(val.isEmpty() ? "General" : val);
                    case 2 -> e.setDescription(val);
                }
                store.save();
                fireTableCellUpdated(row, col);
            }

            @Override
            public Object getValueAt(int row, int col) {
                List<FilePathEntry_littlespidy> list = store.getEntries();
                if (row < 0 || row >= list.size()) return null;
                FilePathEntry_littlespidy e = list.get(row);
                return switch (col) {
                    case 0 -> e.getPath();
                    case 1 -> e.getCategory();
                    case 2 -> e.getDescription();
                    default -> null;
                };
            }
        }
    }
}
